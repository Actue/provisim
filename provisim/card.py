"""UICC file-system navigation.

Covers ICC_SelectDir / ICC_SelectFile / ICC_BinaryFileRead / ICC_RecordFileRead
(and the Write counterparts) from ICCAPI.dll, on top of pyscard.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from . import codec
from .apdu import Apdu, CardError, PinRetryError, exchange
from .files import APP_AID, APP_LOCATION, AID_USIM, App, EfDef, FileStructure, lookup_ef

CLA_USIM = 0x00  # 3GPP UICC uses CLA 0x0X

# CHV / ADM key references (TS 31.102 table):
#   01 PIN1, 02 PIN2, 08 ADM (common on blank CN programmables),
#   some vendors use 0A/0B.
PIN1_REF = 0x01
PIN2_REF = 0x02
ADM_REF = 0x08


@dataclass
class Fcp:
    """Parsed File Control Parameter (FCP template, ISO 7816-4)."""
    fid: Optional[str] = None
    df_name: Optional[str] = None
    size: Optional[int] = None          # transparent: byte size
    record_len: Optional[int] = None
    record_count: Optional[int] = None
    sfi: Optional[int] = None
    structure: Optional[FileStructure] = None
    lifecycle: Optional[str] = None
    raw: bytes = b""
    tag_security: Dict[int, bytes] = field(default_factory=dict)

    @property
    def record_based(self) -> bool:
        return self.structure in (FileStructure.LINEAR_FIXED, FileStructure.CYCLIC)


def parse_fcp(data: bytes) -> Fcp:
    """Parse SELECT response data (FCP template, tag 0x62)."""
    fcp = Fcp(raw=data)
    if not data or data[0] != 0x62:
        return fcp  # some GSM cards return 3F00-style FCI; treat as opaque

    def tlvs(buf: bytes):
        i = 0
        while i + 1 < len(buf):
            tag = buf[i]
            if tag & 0x1F == 0x1F:  # 2-byte tag, rare here
                tag = (tag << 8) | buf[i + 1]
                i += 1
            ln = buf[i + 1]
            yield tag, buf[i + 2 : i + 2 + ln]
            i += 2 + ln

    body = data[1:]  # 0x62 <len> ... (len may be 0x81-prefixed, tolerated)
    if body and body[0] == 0x81:
        body = body[2:]
    elif body:
        body = body[1:]
    for tag, val in tlvs(body):
        if tag == 0x80:
            fcp.size = int.from_bytes(val, "big")
        elif tag == 0x81:
            fcp.size = int.from_bytes(val, "big")
        elif tag == 0x82:  # file descriptor (TS 102 221 11.1.1.4.3)
            # byte1: b7 shareable, b6-4 file type, b3-1 structure
            #        (1 transparent, 2 linear fixed, 6 cyclic)
            # byte2 = 0x21 fixed; bytes 3-4 = record length; byte 5 = record count
            if len(val) >= 1:
                kind = val[0] & 0x07
                fcp.structure = {
                    1: FileStructure.TRANSPARENT,
                    2: FileStructure.LINEAR_FIXED,
                    6: FileStructure.CYCLIC,
                }.get(kind)
            if len(val) >= 4:
                fcp.record_len = int.from_bytes(val[2:4], "big")
            if len(val) >= 5:
                fcp.record_count = val[4]
        elif tag == 0x83 and val:
            fcp.fid = val.hex().upper()
        elif tag == 0x84 and val:
            fcp.df_name = val.hex().upper()
        elif tag == 0x88 and val:
            fcp.sfi = val[0]
        elif tag == 0x8A and val:
            fcp.lifecycle = {0x05: "operational-active", 0x01: "creation",
                             0x0D: "terminated"}.get(val[0], f"{val.hex()}") \
                if val else None
        else:
            fcp.tag_security[tag] = val
    return fcp


class UiccCard:
    """High-level session on one card. Create via connect()."""

    def __init__(self, transport):
        self.transport = transport
        self.cla = CLA_USIM
        self.atr = transport.atr
        self.apps: Dict[str, bool] = {}     # app key -> present
        self._current: Optional[Tuple[App, str]] = None  # (app, last fid)

    # -- SELECT -----------------------------------------------------------

    def _exchange(self, cla, ins, p1, p2, data=b"", le=None, context=""):
        return exchange(self.transport, cla, ins, p1, p2, data, le,
                        context=context, log=self.transport.log)

    def select_by_aid(self, aid: str) -> Fcp:
        data = codec.h2b(aid)
        resp = self._exchange(self.cla, 0xA4, 0x04, 0x04, data, le=0, context=f"AID {aid}")
        return parse_fcp(resp)

    def select_by_path(self, path: Sequence[str]) -> Fcp:
        """Select by file path from MF, e.g. ['3F00','7F10'] or ['3F00','2FE2'].

        Single-element paths (the MF itself) use P1=00 (select by file id);
        longer paths use P1=08 (select by path from MF).
        """
        raw = b"".join(codec.h2b(p) for p in path)
        p1 = 0x00 if len(path) == 1 else 0x08
        resp = self._exchange(self.cla, 0xA4, p1, 0x04, raw, le=0,
                              context="/".join(path))
        return parse_fcp(resp)

    def select_ef(self, fid: str) -> Fcp:
        """Select an EF by 2-byte id inside the currently selected app/DF.

        Uses P1=00 (select by file id); more widely accepted than P1=02.
        """
        resp = self._exchange(self.cla, 0xA4, 0x00, 0x04, codec.h2b(fid), le=0,
                              context=f"EF {fid}")
        return parse_fcp(resp)

    def select_app(self, app: App) -> Fcp:
        if app in APP_AID:
            fcp = self.select_by_aid(APP_AID[app])
        else:
            fcp = self.select_by_path(APP_LOCATION[app])
        self._current = (app, None)
        return fcp

    # -- read/write ---------------------------------------------------------

    def read_binary(self, size: Optional[int] = None, sfi: Optional[int] = None) -> bytes:
        """READ BINARY on the selected EF (or by SFI)."""
        chunks = []
        offset = 0
        while True:
            want = min(256, size - offset) if size else 256
            p1 = 0x80 | sfi if sfi is not None else (offset >> 8) & 0x7F
            p2 = offset & 0xFF
            data = self._exchange(self.cla, 0xB0, p1, p2, b"",
                                  le=want or 0, context="READ BINARY")
            chunks.append(data)
            offset += len(data)
            if not size:
                if len(data) < 256:
                    break
            elif offset >= size or not data:
                break
        return b"".join(chunks)

    def update_binary(self, data: bytes, offset: int = 0,
                      sfi: Optional[int] = None) -> None:
        p1 = 0x80 | sfi if sfi is not None else (offset >> 8) & 0x7F
        p2 = offset & 0xFF
        # chunk to keep Lc <= 255
        for i in range(0, len(data), 255):
            self._exchange(self.cla, 0xD6, p1, p2, data[i : i + 255],
                          context="UPDATE BINARY")

    def read_record(self, record: int = 1, sfi: Optional[int] = None,
                    length: int = 255) -> bytes:
        """READ RECORD. Per ISO 7816-4: P1 = record number,
        P2 bits 8..4 = SFI (if used), bits 3..1 = 100 (absolute mode)."""
        p1 = record & 0xFF
        p2 = 0x04
        if sfi is not None:
            p2 |= (sfi & 0x1F) << 3
        return self._exchange(self.cla, 0xB2, p1, p2, b"", le=length,
                              context=f"READ RECORD {record}")

    def update_record(self, record: int, data: bytes,
                      sfi: Optional[int] = None) -> None:
        p1 = record & 0xFF
        p2 = 0x04
        if sfi is not None:
            p2 |= (sfi & 0x1F) << 3
        for i in range(0, len(data), 255):
            self._exchange(self.cla, 0xDC, p1, p2, data[i : i + 255],
                          context=f"UPDATE RECORD {record}")

    # -- EF convenience (uses the files.py table) ---------------------------

    def read_ef(self, key: str, app: Optional[App] = None) -> "EfData":
        """Select + fully read an EF. Returns raw data / records."""
        d = lookup_ef(key, app)
        self.select_app(d.parent)
        fcp = self.select_ef(d.fid)
        if fcp.record_based:
            recs = []
            n = fcp.record_count or 1
            rlen = fcp.record_len or d.size or 32
            for r in range(1, n + 1):
                try:
                    recs.append(self.read_record(r, length=rlen))
                except CardError as e:
                    if e.sw in (0x9402, 0x6A83):  # out of range: stop
                        break
                    raise
            return EfData(d, fcp, records=recs)
        size = fcp.size or d.size or 32
        data = self.read_binary(size)
        return EfData(d, fcp, data=data[:size] if size else data)

    def update_ef_data(self, key: str, data: bytes, app: Optional[App] = None,
                       record: Optional[int] = None) -> None:
        d = lookup_ef(key, app)
        self.select_app(d.parent)
        fcp = self.select_ef(d.fid)
        if fcp.record_based and record is not None:
            self.update_record(record, data)
        elif fcp.record_based:
            # rewrite all records from the blob
            rlen = fcp.record_len or d.size or len(data)
            for i in range(0, len(data), rlen):
                self.update_record(i // rlen + 1, data[i : i + rlen].ljust(rlen, b"\xff"))
        else:
            self.update_binary(data)

    # -- apps / detection ----------------------------------------------------

    def detect_apps(self) -> Dict[str, bool]:
        apps: Dict[str, bool] = {}
        for app, key in ((App.ADF_USIM, "USIM"), (App.ADF_ISIM, "ISIM"),
                         (App.ADF_CSIM, "CSIM")):
            try:
                self.select_app(app)
                apps[key] = True
            except CardError:
                apps[key] = False
        try:
            self.select_app(App.DF_GSM)
            apps["GSM"] = True
        except CardError:
            apps["GSM"] = False
        self.apps = apps
        return apps

    # -- PIN / ADM -------------------------------------------------------------

    def verify_pin(self, ref: int, value: str, context: str = "") -> None:
        """VERIFY CHV. `value` is PIN digits / ADM hex-or-ascii key."""
        if ref == ADM_REF and len(value) == 16 and all(c in "0123456789abcdefABCDEF" for c in value):
            data = codec.h2b(value)          # ADM given as hex
        else:
            data = value.encode("ascii")     # PIN as ASCII
        data = data.ljust(8, b"\xff")
        self._exchange(self.cla, 0x20, 0x00, ref, data, context=context or f"VERIFY CHV{ref}")

    def verify_adm(self, key: str, ref: int = ADM_REF) -> None:
        self.verify_pin(ref, key, context=f"VERIFY ADM (ref {ref:02X})")

    def change_pin(self, ref: int, old: str, new: str) -> None:
        data = (old.encode("ascii").ljust(8, b"\xff")
                + new.encode("ascii").ljust(8, b"\xff"))
        self._exchange(self.cla, 0x24, 0x00, ref, data, context=f"CHANGE CHV{ref}")

    def unblock_pin(self, ref: int, puk: str, new_pin: str) -> None:
        data = (puk.encode("ascii").ljust(8, b"\xff")
                + new_pin.encode("ascii").ljust(8, b"\xff"))
        self._exchange(self.cla, 0x2C, 0x00, ref, data, context=f"UNBLOCK CHV{ref}")

    def disable_pin(self, ref: int, pin: str) -> None:
        data = pin.encode("ascii").ljust(16, b"\xff")
        self._exchange(self.cla, 0x26, 0x00, ref, data, context=f"DISABLE CHV{ref}")

    # -- raw passthrough -----------------------------------------------------

    def transmit_raw(self, hexstr: str) -> Tuple[bytes, int]:
        raw = codec.h2b(hexstr)
        cla, ins, p1, p2 = raw[0], raw[1], raw[2], raw[3]
        rest = raw[4:]
        data, le = b"", None
        if rest:
            lc = rest[0]
            data = rest[1 : 1 + lc]
            tail = rest[1 + lc :]
            if tail:
                le = tail[0]
        resp = exchange(self.transport, cla, ins, p1, p2, data, le,
                        context="raw", log=self.transport.log)
        return resp, 0x9000


@dataclass
class EfData:
    definition: EfDef
    fcp: Fcp
    data: bytes = b""
    records: List[bytes] = field(default_factory=list)

    def hex(self) -> str:
        if self.records:
            return "\n".join(f"{i+1}: {codec.b2h(r)}" for i, r in enumerate(self.records))
        return codec.b2h(self.data)
