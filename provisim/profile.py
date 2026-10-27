"""High-level card profile: read_card() / write_card().

Equivalent of the GRSIMWrite "Read Card" / "Write Card" buttons, minus the
GUI. Read works without ADM for most EFs; write requires the ADM key and
is dry-run by default.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional

from . import codec
from .card import CardError, UiccCard
from .files import App


@dataclass
class SimProfile:
    atr: str = ""
    apps: Dict[str, bool] = field(default_factory=dict)
    iccid: Optional[str] = None
    imsi: Optional[str] = None
    acc: Optional[Dict] = None
    smsp: Optional[str] = None
    spn: Optional[Dict] = None
    fplmn: Optional[List[str]] = None
    ehplmn: Optional[List[str]] = None
    plmnwact: Optional[List[Dict]] = None
    oplmnwact: Optional[List[Dict]] = None
    hplmnwact: Optional[List[Dict]] = None
    gid1: Optional[str] = None
    gid2: Optional[str] = None
    msisdn: Optional[str] = None
    ecc: Optional[List[Dict]] = None
    ad: Optional[Dict] = None
    li: Optional[str] = None
    # ISIM application
    isim: Dict[str, object] = field(default_factory=dict)
    # everything else, hex, for debugging / round-trip
    raw: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_json(cls, s: str) -> "SimProfile":
        d = json.loads(s)
        base = {f: d.get(f) for f in cls.__dataclass_fields__ if f in d}
        return cls(**base)


def _safe(fn, default=None):
    try:
        return fn()
    except CardError:
        return default


def read_profile(card: UiccCard) -> SimProfile:
    p = SimProfile(atr=codec.b2h(card.atr))
    p.apps = card.detect_apps()

    ef_iccid = card.read_ef("ICCID")
    p.iccid = codec.decode_iccid(ef_iccid.data)
    p.raw["ICCID"] = ef_iccid.hex()

    app = App.ADF_USIM if p.apps.get("USIM") else App.DF_GSM
    key_prefix = "" if p.apps.get("USIM") else "_GSM"

    def rf(key):
        return _safe(lambda: card.read_ef(key + key_prefix, app), None)

    if ef := rf("IMSI"):
        p.imsi = codec.decode_imsi(ef.data)
        p.raw["IMSI"] = ef.hex()
    if ef := rf("ACC"):
        p.acc = codec.decode_acc(ef.data)
        p.raw["ACC"] = ef.hex()
    if ef := rf("SPN"):
        p.spn = codec.decode_spn(ef.data)
        p.raw["SPN"] = ef.hex()
    if ef := rf("FPLMN"):
        p.fplmn = codec.decode_plmn_list(ef.data)
        p.raw["FPLMN"] = ef.hex()
    if ef := rf("GID1"):
        p.gid1 = codec.decode_gid(ef.data)
        p.raw["GID1"] = ef.hex()
    if ef := rf("GID2"):
        p.gid2 = codec.decode_gid(ef.data)
        p.raw["GID2"] = ef.hex()
    if ef := rf("AD"):
        p.ad = codec.decode_ad(ef.data)
        p.raw["AD"] = ef.hex()
    if ef := rf("LI"):
        p.li = ef.data.rstrip(b"\xff").decode("ascii", "ignore")
        p.raw["LI"] = ef.hex()

    if p.apps.get("USIM"):
        if ef := rf("EHPLMN"):
            p.ehplmn = codec.decode_plmn_list(ef.data)
            p.raw["EHPLMN"] = ef.hex()
        if ef := rf("PLMNWACT"):
            p.plmnwact = codec.decode_plmn_w_act(ef.data)
            p.raw["PLMNwAcT"] = ef.hex()
        if ef := rf("OPLMNWACT"):
            p.oplmnwact = codec.decode_plmn_w_act(ef.data)
            p.raw["OPLMNwAcT"] = ef.hex()
        if ef := rf("HPLMNWACT"):
            p.hplmnwact = codec.decode_plmn_w_act(ef.data)
            p.raw["HPLMNwAcT"] = ef.hex()
        if ef := rf("ECC"):
            p.ecc = [codec.decode_ecc_record(r) for r in ef.records]
            p.raw["ECC"] = ef.hex()

    # DF_TELECOM / USIM shared records
    msisdn_key = "MSISDN_USIM" if p.apps.get("USIM") else "MSISDN"
    smsp_key = "SMSP_USIM" if p.apps.get("USIM") else "SMSP"
    if ef := _safe(lambda: card.read_ef(msisdn_key), None):
        rec = codec.decode_msisdn_record(ef.records[0]) if ef.records else {}
        p.msisdn = rec.get("number") or None
        p.raw["MSISDN"] = ef.hex()
    if ef := _safe(lambda: card.read_ef(smsp_key), None):
        p.smsp = codec.decode_smsp_record(ef.records[0]).get("sca") or None
        p.raw["SMSP"] = ef.hex()

    # ISIM
    if p.apps.get("ISIM"):
        isim: Dict[str, object] = {}
        if ef := _safe(lambda: card.read_ef("DOMAIN"), None):
            isim["domain"] = ef.data.rstrip(b"\xff").decode("ascii", "ignore")
            p.raw["ISIM.DOMAIN"] = ef.hex()
        if ef := _safe(lambda: card.read_ef("IMPI"), None):
            isim["impi"] = ef.data.rstrip(b"\xff").decode("ascii", "ignore")
            p.raw["ISIM.IMPI"] = ef.hex()
        if ef := _safe(lambda: card.read_ef("IMPU"), None):
            isim["impu"] = [r.rstrip(b"\xff").decode("ascii", "ignore")
                            for r in ef.records if r.strip(b"\xff")]
            p.raw["ISIM.IMPU"] = ef.hex()
        if ef := _safe(lambda: card.read_ef("PCSCF"), None):
            isim["pcscf"] = [r.rstrip(b"\xff").decode("ascii", "ignore")
                             for r in ef.records if r.strip(b"\xff")]
            p.raw["ISIM.PCSCF"] = ef.hex()
        p.isim = isim

    return p


# ------------------------------------------------------------- writing

@dataclass
class WriteOp:
    field: str
    ef_key: str
    app: App
    data: Optional[bytes] = None
    record: Optional[int] = None
    note: str = ""

    def describe(self) -> str:
        where = f"{self.ef_key}" + (f" record {self.record}" if self.record else "")
        return f"{self.field:<12} -> {where:<14} {codec.b2h(self.data) if self.data else ''}"


def build_write_ops(profile: SimProfile) -> List[WriteOp]:
    """Translate a profile into the list of EF updates it implies."""
    ops: List[WriteOp] = []
    usim = profile.apps.get("USIM", True) if profile.apps else True
    app = App.ADF_USIM if usim else App.DF_GSM
    k = "" if usim else "_GSM"
    d = profile.to_dict()

    if profile.iccid:
        ops.append(WriteOp("ICCID", "ICCID", App.MF,
                           codec.encode_iccid(profile.iccid)))
    if profile.imsi:
        ops.append(WriteOp("IMSI", f"IMSI{k}", app,
                           codec.encode_imsi(profile.imsi)))
    if profile.spn and isinstance(profile.spn, dict) and profile.spn.get("name"):
        spn = profile.spn
        cond = spn.get("display_condition", 0)
        ops.append(WriteOp("SPN", f"SPN{k}", app,
                           codec.encode_spn(spn["name"], int(cond or 0))))
    if profile.fplmn is not None:
        ops.append(WriteOp("FPLMN", f"FPLMN{k}", app,
                           codec.encode_plmn_list(profile.fplmn, 4)))
    if profile.ehplmn is not None:
        ops.append(WriteOp("EHPLMN", "EHPLMN", app,
                           codec.encode_plmn_list(profile.ehplmn, 5)))
    if profile.gid1:
        ops.append(WriteOp("GID1", f"GID1{k}", app,
                           codec.h2b(profile.gid1.ljust(8, "0"))))
    if profile.gid2:
        ops.append(WriteOp("GID2", f"GID2{k}", app,
                           codec.h2b(profile.gid2.ljust(8, "0"))))
    if profile.ad and isinstance(profile.ad, dict):
        ops.append(WriteOp("AD", f"AD{k}", app,
                           codec.encode_ad(profile.ad.get("mcc", ""),
                                           profile.ad.get("mnc", ""))))
    if isinstance(profile.acc, dict) and profile.acc.get("classes"):
        ops.append(WriteOp("ACC", f"ACC{k}", app,
                           codec.encode_acc([int(c) for c in profile.acc["classes"]])))
    if profile.msisdn:
        ops.append(WriteOp("MSISDN", "MSISDN_USIM" if usim else "MSISDN", app,
                           codec.encode_msisdn_record(profile.msisdn)))
    if profile.smsp:
        ops.append(WriteOp("SMSP", "SMSP_USIM" if usim else "SMSP", app,
                           codec.encode_smsp_record(profile.smsp),
                           record=1, note="record 1 only"))
    if profile.li:
        ops.append(WriteOp("LI", "LI", app,
                           profile.li.encode("ascii").ljust(2, b"\xff")))
    if profile.oplmnwact:
        blob = b"".join(codec.encode_plmn_w_act(e["plmn"], int(e["act_mask"]))
                        for e in profile.oplmnwact if e.get("plmn"))
        blob = blob.ljust(40, b"\xff")
        ops.append(WriteOp("OPLMNwAcT", "OPLMNWACT", app, blob[:40]))
    return ops


def write_profile(card: UiccCard, profile: SimProfile, adm: str,
                  dry_run: bool = True, adm_ref: int = 0x08,
                  only: Optional[List[str]] = None) -> List[str]:
    """Apply a profile. `adm` is the ADM key (hex or ASCII, 8 bytes).

    Returns a log of executed / planned operations. dry_run=True only
    prints the operations without touching the card.
    """
    ops = build_write_ops(profile)
    if only:
        ops = [o for o in ops if o.field in only]
    log: List[str] = []
    log.append(f"{len(ops)} update(s) planned" + (" [DRY RUN]" if dry_run else ""))
    for op in ops:
        log.append("  " + op.describe())
    if dry_run:
        return log
    card.verify_adm(adm, adm_ref)
    log.append(f"ADM verified (ref {adm_ref:02X})")
    for op in ops:
        card.update_ef_data(op.ef_key, op.data, app=op.app, record=op.record)
        log.append(f"  done: {op.field}")
    return log
