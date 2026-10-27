"""Elementary-file directory table.

Sources: 3GPP TS 31.102 (USIM), TS 31.103 (ISIM), TS 31.102 annex /
3GPP2 for CSIM, GSM 11.11 (classic SIM). The set mirrors the fields the
GRSIMWrite GUI exposes (see GRSIMWrite.grsp: TabGSM / GrpLTE / TabISIM).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Tuple


class FileStructure(str, Enum):
    TRANSPARENT = "transparent"
    LINEAR_FIXED = "linear_fixed"
    CYCLIC = "cyclic"


AID_USIM = "A0000000871002"
AID_ISIM = "A0000000871004"
AID_CSIM = "A0000003431002"  # 3GPP2 RID
# LY14 blank programmable card (GRSIMWrite CardInfo, private USIM AID variant)
AID_LY14 = "A0000000871002FF86FF0389FFFFFFFF"


class App(str, Enum):
    MF = "MF"
    DF_TELECOM = "DF_TELECOM"
    DF_GSM = "DF_GSM"
    ADF_USIM = "ADF_USIM"
    ADF_ISIM = "ADF_ISIM"
    ADF_CSIM = "ADF_CSIM"


# Where each app lives: either a DFID path from MF, or an AID.
APP_LOCATION: Dict[App, Tuple[str, ...]] = {
    App.MF: ("3F00",),
    App.DF_TELECOM: ("3F00", "7F10"),
    App.DF_GSM: ("3F00", "7F20"),
}
APP_AID: Dict[App, str] = {
    App.ADF_USIM: AID_USIM,
    App.ADF_ISIM: AID_ISIM,
    App.ADF_CSIM: AID_CSIM,
}


@dataclass(frozen=True)
class EfDef:
    name: str                       # short name, e.g. "IMSI"
    fid: str                        # file id, e.g. "6F07"
    parent: App
    structure: FileStructure
    size: Optional[int] = None      # bytes (transparent) or record length
    records: Optional[int] = None   # record count for record-based files
    sfi: Optional[int] = None       # short file identifier if fixed
    writable: bool = True
    adm_protected: bool = True      # needs ADM/PIN2 to update, usually
    description: str = ""

    @property
    def record_based(self) -> bool:
        return self.structure in (FileStructure.LINEAR_FIXED, FileStructure.CYCLIC)


def _ef(name, fid, parent, structure, size=None, records=None,
        sfi=None, writable=True, adm=True, desc=""):
    return EfDef(name, fid, parent, structure, size, records, sfi,
                 writable, adm, desc)


T, LF, CY = FileStructure.TRANSPARENT, FileStructure.LINEAR_FIXED, FileStructure.CYCLIC

EF: Dict[str, EfDef] = {
    # -- MF ------------------------------------------------------------
    "ICCID": _ef("ICCID", "2FE2", App.MF, T, 10, adm=False,
                 desc="Integrated Circuit Card ID (E.118)"),
    # -- classic GSM SIM (GSM 11.11, DF_GSM) ----------------------------
    "IMSI_GSM": _ef("IMSI", "6F07", App.DF_GSM, T, 9),
    "SPN_GSM": _ef("SPN", "6F46", App.DF_GSM, T, 17, desc="Service Provider Name"),
    "ACC_GSM": _ef("ACC", "6F78", App.DF_GSM, T, 2, desc="Access Control Class"),
    "FPLMN_GSM": _ef("FPLMN", "6F7B", App.DF_GSM, T, 12,
                     desc="Forbidden PLMNs (4 entries)"),
    "GID1_GSM": _ef("GID1", "6F3E", App.DF_GSM, T, 4),
    "GID2_GSM": _ef("GID2", "6F3F", App.DF_GSM, T, 4),
    "AD_GSM": _ef("AD", "6FAD", App.DF_GSM, T, 4,
                  desc="Administrative data (MCC/MNC)"),
    # -- DF_TELECOM ------------------------------------------------------
    "ADN": _ef("ADN", "6F3A", App.DF_TELECOM, LF, 32, desc="Abbreviated dialling numbers"),
    "MSISDN": _ef("MSISDN", "6F40", App.DF_TELECOM, LF, 32, desc="own number"),
    "SMSP": _ef("SMSP", "6F42", App.DF_TELECOM, LF, 32, desc="SMS parameters (SMSC)"),
    "SMSS": _ef("SMSS", "6F43", App.DF_TELECOM, T, 2),
    # -- ADF_USIM (TS 31.102) --------------------------------------------
    "LI": _ef("LI", "6F05", App.ADF_USIM, T, desc="Language indication"),
    "IMSI": _ef("IMSI", "6F07", App.ADF_USIM, T, 9),
    "UST": _ef("UST", "6F41", App.ADF_USIM, T, adm=False, desc="USIM service table"),
    "GID1": _ef("GID1", "6F3E", App.ADF_USIM, T, 4),
    "GID2": _ef("GID2", "6F3F", App.ADF_USIM, T, 4),
    "MSISDN_USIM": _ef("MSISDN", "6F40", App.ADF_USIM, LF, 32),
    "SMSP_USIM": _ef("SMSP", "6F42", App.ADF_USIM, LF, 32),
    "ACC": _ef("ACC", "6F78", App.ADF_USIM, CY, 2),
    "FPLMN": _ef("FPLMN", "6F7B", App.ADF_USIM, T, 12),
    "LOCI": _ef("LOCI", "6F7E", App.ADF_USIM, T, 11),
    "AD": _ef("AD", "6FAD", App.ADF_USIM, T, 4),
    "SPN": _ef("SPN", "6F46", App.ADF_USIM, T, 17),
    "PLMNWACT": _ef("PLMNwAcT", "6F60", App.ADF_USIM, LF, 40, desc="user PLMN+AcT list"),
    "OPLMNWACT": _ef("OPLMNwAcT", "6F61", App.ADF_USIM, LF, 40, desc="operator PLMN+AcT list"),
    "HPLMNWACT": _ef("HPLMNwAcT", "6F62", App.ADF_USIM, LF, 40,
                     desc="HPLMN+AcT search period"),
    "ECC": _ef("ECC", "6FB7", App.ADF_USIM, LF, desc="emergency call codes"),
    "EHPLMN": _ef("EHPLMN", "6FE4", App.ADF_USIM, T, desc="equivalent HPLMN list"),
    # -- ADF_ISIM (TS 31.103) ---------------------------------------------
    "DOMAIN": _ef("DOMAIN", "6F03", App.ADF_ISIM, T, desc="home network domain"),
    "IMPU": _ef("IMPU", "6F04", App.ADF_ISIM, LF, desc="public identities"),
    "IMPI": _ef("IMPI", "6F05", App.ADF_ISIM, T, desc="private identity"),
    "PCSCF": _ef("PCSCF", "6F09", App.ADF_ISIM, LF, desc="P-CSCF addresses"),
    # -- ADF_CSIM (3GPP2 C.S0023) ------------------------------------------
    "IMSI_T": _ef("IMSI_T", "6F82", App.ADF_CSIM, T, 9, desc="CDMA IMSI_T"),
    "CSP": _ef("CSP", "6F82", App.ADF_CSIM, T, desc="CDMA service profile"),
}


def lookup_ef(name: str, app: Optional[App] = None) -> EfDef:
    """Find an EF definition by (unqualified) name, optionally app-scoped.

    Names like 'IMSI' resolve to the USIM variant first; use the keyed
    form ('IMSI_GSM') or pass `app` when both exist.
    """
    if name in EF:
        return EF[name]
    candidates = [d for d in EF.values() if d.name == name]
    if app is not None:
        candidates = [d for d in candidates if d.parent == app] or candidates
    if len(candidates) != 1:
        known = ", ".join(sorted(EF))
        raise KeyError(f"EF {name!r} not resolvable (known keys: {known})")
    return candidates[0]
