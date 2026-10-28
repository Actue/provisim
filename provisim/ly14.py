"""LY14 / Watchdata-family blank programmable-card backend.

**Reverse-engineered from GRSIMWrite.exe (4.4.6)** — the vendor GUI stores
every card command as an ASCII-hex string in its CODE section; this module
transcribes them. Four protocol generations exist:

===========  ==========================  ============================
generation   secret writes              unlock / ADM
===========  ==========================  ============================
7FF0 (LY14)  A0D6 into DF 7FF0/EF 0006  VERIFY ADM keyref 0x0B
             (Ki@off 1, OPC@off 0x11)
gen4         A0FB <P2> Lc <magic><key>   A0FB FFFF 08 [SADM]
             slots: P2= 00 PIN1/KI, 08   VERIFY keyref 0x0A
             PUK1, 10 OPC, 21 PIN2,
             29 PUK2, 3F ADM
gen3         00D5 1C00 [Ki], 00D5 0157   00E3 0000 08 [SADM]
             [OPC], 00D4 1B00 <alg byte>
record-w     A0D4 3A01 [PIN1] etc.       VERIFY ADM keyref 0x0B/04
===========  ==========================  ============================

Extra gems found while reversing (confirmed by Hex-Rays decompilation of the
write-card master functions sub_4B15E8 / sub_4B01D0 / sub_4B268C):

* ``A0 92 00 00 10`` — READ the 16-byte Ki back (supported by some cards;
  that is how the GUI "Check Card" shows Ki).
* ``A0 96 00 01/02`` — read algorithm State I / State II.
* gen3 algorithm selectors: ``00D4 1B00 01 <byte>`` (LTE_ALG) and
  ``00D4 1B01 01 <byte>`` (GSM_ALG); A0D6-generation uses
  SELECT ``2F03`` then ``A0D6 0002 01 <byte>`` ("USIM ALG").
  Candidate bytes seen beside the code: ``0A`` and ``FF`` (e.g. MLG vs XOR —
  which is which still needs a live capture).
* ``00D5 0258 05 <5B>`` — LTE_R write; ``00D5 0382 50 ...`` — LTE_C.
* Disable/Enable primitives: ``00D8 0000 01 00`` GSM off/on, plus
  ``02 7F20 FFFF``-style clears per DF (GSM/USIM/CDMA/CSIM).
* On the 7FF0 generation Ki/OPC are stored redundantly in EFs
  ``0006``, ``000F`` and ``0012`` — the GUI writes all three.

Full per-card-type initialisation sequences (CREATE FILE storms + commit)
live in ``ly14_templates.py``: 13 templates extracted verbatim.
Use ``replay_template()`` to blank-and-rebuild a card exactly like the GUI.

Everything here is a WRITE to your own blank card. Verify the reader has
the right card in it before calling; ADM failure counters are limited.
"""

from __future__ import annotations

from typing import Dict, List, Optional

from . import codec
from .apdu import CardError, exchange
from .card import UiccCard
from .files import AID_LY14

# 8-byte magics prepended to gen4 (A0FB) secret payloads, per VA 49F0A0+.
FB_MAGIC = {
    "PIN1": "5121239D2455370B",
    "PIN2": "5121239D2455370B",
    "PUK1": "5121239D2455370B",
    "PUK2": "5121239D2455370B",
    "ADM": "5121239D2455370B",
    "LTE_KI": "7FACB75076880506",
}
FB_MAGIC_OPC_HEAD = "1034D5C56869820401"  # 9 bytes, then 16-byte OPC

# gen4 slot P2 values (from A0FB P2 table)
FB_SLOT = {"PIN1": 0x00, "PUK1": 0x08, "LTE_OPC": 0x10,
           "PIN2": 0x21, "PUK2": 0x29, "ADM": 0x3F, "LTE_KI": 0x00}

# record-w slot encodings (A0D4 P1P2), per VA 49C954+
RW_SLOT = {"PIN1": "3A01", "PIN2": "3A02", "PUK1": "3B00",
           "PUK2": "3B02", "ADM": "3A05"}

ADM_REF_LY14 = 0x0B   # A0 20 00 0B 08 <ADM>  (LY14 / A0D4 generation)
ADM_REF_GEN4 = 0x0A   # 00 20 00 0A 08 <SADM> (gen4 FB generation)

ASCII_MARKERS = {"PIN1", "PIN2", "PUK1", "PUK2", "ADM", "ADM1", "ADM2",
                 "SADM", "NAI_PASS", "SIP_PASS", "MIP_PASS", "PIN1_PUK1"}


class Ly14Card(UiccCard):
    """Blank-programmable card operations (private command set)."""

    PRIVATE_AID = AID_LY14
    DEFAULT_ADM_HEX = "3838383838383838"  # ASCII '88888888'

    # ---------------------------------------------------------- detection

    def is_ly14(self) -> bool:
        try:
            self.select_private_app()
            return True
        except CardError:
            return False

    def select_private_app(self):
        return self.select_by_aid(self.PRIVATE_AID)

    def probe(self) -> Dict[str, bool]:
        """Fire harmless read-only private probes, report which command set
        this card answers. (6D00 = INS not supported.)

        Probes both CLA=A0 (classic T=0 LY14 cards) and CLA=00 (T=1
        variants — the T=1 cards reject CLA A0 with 6E00, which is NOT
        'command missing'). Also notes whether VERIFY wants case-4
        (data + Le) — the BHDMS/LY14 T=1 family does.
        """
        result = {}
        for name, a0cmd in {
            "gen4_fb_read_ki": "A092000010",
            "gen4_state1": "A096000100",
            "gen4_state2": "A096000200",
        }.items():
            c00 = "00" + a0cmd[2:]
            result[name] = self._try_send(a0cmd, name + " claA0") or \
                self._try_send(c00, name + " cla00")
        result["df_7ff0"] = (self._try_send("A0A40804043F007FF0", "7FF0 A0") or
                             self._try_send("00A40804043F007FF0", "7FF0 00"))
        # case-4 VERIFY detection: Lc=08 data + Le=08 is the accepted form
        # on the T=1 family; plain case-3 gets 6700/6C there.
        result["verify_case4"] = False
        try:
            exchange(self.transport, 0x00, 0x20, 0x00, 0x0B,
                     b"\x38" * 8, 0x08, context="case4 probe",
                     log=self.transport.log)
            result["verify_case4"] = True
        except CardError:
            pass
        return result

    # ---------------------------------------------------------- raw send

    def _send_hex(self, hexcmd: str, context: str = "") -> bytes:
        raw = codec.h2b(hexcmd)
        cla, ins, p1, p2 = raw[:4]
        rest = raw[4:]
        lc = rest[0] if rest else 0
        data = rest[1 : 1 + lc]
        le = None
        tail = rest[1 + lc :]
        if tail:
            le = tail[0]
        return exchange(self.transport, cla, ins, p1, p2, data, le,
                        context=context or hexcmd, log=self.transport.log)

    def _try_send(self, hexcmd: str, context: str) -> bool:
        try:
            self._send_hex(hexcmd, context)
            return True
        except CardError:
            return False

    # ---------------------------------------------------------- ADM

    def verify_adm(self, key: str, ref: int = ADM_REF_LY14) -> None:
        """LY14 family: A0 20 00 <ref> 08 <8 ADM bytes>. The GUI default is
        hex '3838383838383838' (ASCII '88888888' as bytes on the wire)."""
        key_bytes = codec.h2b(key) if len(key) == 16 else key.encode("ascii")
        self._send_hex(f"A02000{ref:02X}08" + key_bytes.hex().upper(),
                       f"VERIFY ADM ref {ref:02X}")

    def verify_default_adm(self, ref: int = ADM_REF_LY14) -> None:
        self.verify_adm(self.DEFAULT_ADM_HEX, ref)

    # ---------------------------------------------------------- readback

    def read_ki(self) -> bytes:
        """A0 92 00 00 10 — some generations allow reading the 16-byte Ki."""
        return exchange(self.transport, 0xA0, 0x92, 0x00, 0x00, b"", 0x10,
                        context="read Ki (A092)", log=self.transport.log)

    def read_state(self, which: int = 1) -> bytes:
        """A0 96 00 01/02 — algorithm State I / State II."""
        return exchange(self.transport, 0xA0, 0x96, 0x00, which, b"", 0x00,
                        context=f"State {which}", log=self.transport.log)

    # ---------------------------------------------------------- gen4 (A0FB)

    def _fb_send(self, p2: int, body: bytes) -> bytes:
        return exchange(self.transport, 0xA0, 0xFB, 0x00, p2, body,
                        context=f"A0FB P2={p2:02X}", log=self.transport.log)

    def fb_unlock_sadm(self, sadm: str) -> None:
        """A0 FB FF FF 08 [SADM] — master unlock before secret writes."""
        self._send_hex("A0FBFFFF08" + self._key8(sadm, "SADM").hex().upper(),
                       "A0FB SADM unlock")

    def fb_write(self, secret: str, value: str) -> bytes:
        """gen4 secret write: PIN1/PIN2/PUK1/PUK2/ADM (<=8 ascii) or
        LTE_KI/LTE_OPC (32 hex chars = 16 bytes)."""
        secret = secret.upper()
        if secret == "LTE_OPC":
            body = codec.h2b(FB_MAGIC_OPC_HEAD) + codec.h2b(value)
            return self._fb_send(FB_SLOT[secret], body)
        if secret == "LTE_KI":
            return self._fb_send(FB_SLOT[secret],
                                 codec.h2b(FB_MAGIC[secret]) + codec.h2b(value))
        if secret not in FB_SLOT or secret not in FB_MAGIC:
            raise ValueError(f"unknown gen4 secret {secret!r}")
        return self._fb_send(FB_SLOT[secret],
                             codec.h2b(FB_MAGIC[secret]) + self._key8(value, secret))

    # 7FF0 generation stores Ki/OPc redundantly in EFs 0006/000F/0012
    KI_EFS = ("0006", "000F", "0012")

    def _write_7ff0_secret(self, payload_hex: str, offset: int,
                           what: str) -> None:
        self._send_hex("A0A40804043F007FF0", "select 3F00/7FF0")
        for ef in self.KI_EFS:
            try:
                self._send_hex(f"A0A4000402{ef}", f"select EF {ef}")
                self._send_hex(f"A0D6{offset:04X}10{payload_hex}",
                               f"write {what} @ {ef} off {offset:#06x}")
            except CardError as e:
                # not all cards carry all three mirror EFs; skip missing ones
                print(f"    [skip] EF {ef}: {e}")

    def set_ki(self, ki_hex: str) -> None:
        """Write LTE/USIM Ki. Dispatches on card generation detected via
        probe(): 7FF0 DF present -> A0D6 path (mirrored in 0006/000F/0012),
        else gen4 A0FB / gen3 00D5."""
        p = self.probe()
        if p.get("df_7ff0"):
            self._write_7ff0_secret(ki_hex, 0x0001, "Ki")
        elif p.get("gen4_fb_read_ki"):
            self.fb_write("LTE_KI", ki_hex)
        else:
            # gen3: 00 D5 1C 00 10 <Ki>
            self._send_hex("00D51C0010" + ki_hex, "00D5 write Ki")

    def set_opc(self, opc_hex: str) -> None:
        p = self.probe()
        if p.get("df_7ff0"):
            self._write_7ff0_secret(opc_hex, 0x0011, "OPc")
        elif p.get("gen4_fb_read_ki"):
            self.fb_write("LTE_OPC", opc_hex)
        else:
            self._send_hex("00D5015710" + opc_hex, "00D5 write OPc")

    def set_algorithm(self, alg_byte: int, lte: bool = True) -> None:
        """gen3 algorithm selector: 00D4 1B00 01 <byte> (LTE_ALG) or
        00D4 1B01 01 <byte> (GSM_ALG). A0D6-generation uses
        SELECT 2F03 + A0D6 0002 01 <byte> (pass lte=True, gen='a0d6').

        alg_byte candidates seen in the binary: 0A, FF (MLG vs XOR —
        pin down with read_state() on a live card)."""
        if lte:
            self._send_hex(f"00D41B0001{alg_byte:02X}", "LTE_ALG")
        else:
            self._send_hex(f"00D41B0101{alg_byte:02X}", "GSM_ALG")

    def set_algorithm_a0d6(self, alg_byte: int) -> None:
        """A0D6 generation 'USIM ALG': SELECT 2F03 then A0D6 0002 01."""
        self._send_hex("A0A40004022F03", "select 2F03")
        self._send_hex(f"A0D6000201{alg_byte:02X}", "USIM ALG")

    def set_lte_r(self, five_bytes_hex: str) -> None:
        """00D5 0258 05 <5 bytes> — LTE_R parameter write."""
        self._send_hex("00D5025805" + five_bytes_hex, "LTE_R")

    def set_lte_c(self, payload_hex: str) -> None:
        """00D5 0382 50 <payload> — LTE_C parameter write."""
        self._send_hex("00D5038250" + payload_hex, "LTE_C")

    # ---------------------------------------------------------- CHV writes

    def set_pin(self, pin1: str, puk1: str, pin2: str = "1234",
                puk2: str = "88888888", adm: Optional[str] = None) -> List[str]:
        """Write PIN/PUK set. Record-write generation (A0D4 3Axx/3Bxx);
        gen4 cards should use fb_write() per secret instead."""
        log: List[str] = []
        for secret, value in (("PIN1", pin1), ("PIN2", pin2),
                              ("PUK1", puk1), ("PUK2", puk2),
                              ("ADM", adm or self.DEFAULT_ADM_HEX)):
            p1p2 = RW_SLOT[secret]
            exchange(self.transport, 0xA0, 0xD4, int(p1p2[:2], 16),
                     int(p1p2[2:], 16), self._key8(value, secret),
                     context=f"set {secret}", log=self.transport.log)
            log.append(f"{secret} written")
        return log

    def set_pin1_initial(self, pin: str) -> None:
        """A0 52 00 00 08 <pin> — initial PIN1 set during card build."""
        exchange(self.transport, 0xA0, 0x52, 0x00, 0x00,
                 self._key8(pin, "PIN1"), context="A052 set PIN1",
                 log=self.transport.log)

    # ---------------------------------------------------------- templates

    def replay_template(self, index: int, values: Optional[Dict[str, str]] = None,
                        dry_run: bool = True, pin: str = "12341234") -> List[str]:
        """Replay one of the 13 card-initialisation templates verbatim:
        set PIN1 (A052), CREATE FILE xN (A0E0), fill initial data
        (A0D6/A0DC), commit (A053). This WIPES the card.

        values: {"IMSI": "4600..."} etc. for [PLACEHOLDER] substitution;
        markers default to GUI defaults when absent.
        """
        from .ly14_templates import TEMPLATES

        template = TEMPLATES[index]
        ops: List[str] = []
        for va in sorted(template):
            cmd = template[va]
            cmd = cmd.replace("3132333431323334", pin.encode().hex().upper())
            cmd = self._substitute(cmd, values or {})
            ops.append(f"{va:#010x}: {cmd}")
        if dry_run:
            return ops
        for op in ops:
            raw = codec.h2b(op.split(": ", 1)[1])
            cla, ins, p1, p2 = raw[:4]
            lc = raw[4]
            exchange(self.transport, cla, ins, p1, p2, raw[5:5 + lc],
                     context=op[:28], log=self.transport.log)
        return ops

    # ---------------------------------------------------------- helpers

    @staticmethod
    def _key8(value: str, marker: str) -> bytes:
        """Accept either 16 hex chars (raw bytes, e.g. ADM '38383838...')
        or <=8 ascii chars (PIN '1234'), pad the latter with 0xFF."""
        if len(value) == 16 and all(c in "0123456789abcdefABCDEF" for c in value):
            return codec.h2b(value)
        b = value.encode("ascii")
        if len(b) > 8:
            raise ValueError(f"{marker}: need <=8 ascii chars or 16 hex chars, "
                             f"got {value!r}")
        return b.ljust(8, b"\xff")

    @classmethod
    def _substitute(cls, cmd: str, values: Dict[str, str]) -> str:
        import re
        for marker in set(re.findall(r"\[([A-Z0-9_]+)\]", cmd)):
            if marker not in values:
                continue  # leave literal; replay will fail loudly if real
            v = cls._key8(values[marker], marker) if len(values[marker]) <= 16 \
                else codec.h2b(values[marker])
            cmd = cmd.replace(f"[{marker}]", v.hex().upper())
        return cmd
