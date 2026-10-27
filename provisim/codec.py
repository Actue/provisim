"""EF payload codecs.

Replaces the BCD/hex helpers of ICCAPI.dll (AsciiToBCD, BCDToAscii, ...)
plus the field encodings the GUI hard-codes in GRSIMWrite.exe.

Conventions: EF payloads are bytes; user-visible values are str/int.
BCD on SIM cards is nibble-swapped ("460 00" -> 64 F0 00).
"""

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

PAD_NIBBLE = 0xF


# ---------------------------------------------------------------- BCD basics

def swap_nibbles(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        out.append(((b & 0x0F) << 4) | (b >> 4))
    return bytes(out)


def decode_bcd(data: bytes, strip_pad: bool = True) -> str:
    """Swapped-nibble BCD digits: b'\\x64\\xf0' -> '4604'? -> '4640'... see note.

    Each byte holds two digits, low nibble first: 0x64 -> '4','6'.
    """
    digits = []
    for b in data:
        digits.append(b & 0x0F)
        digits.append(b >> 4)
    if strip_pad:
        while digits and digits[-1] == PAD_NIBBLE:
            digits.pop()
    if any(d > 9 for d in digits):
        raise ValueError(f"invalid BCD nibble in {data.hex()}")
    return "".join(str(d) for d in digits)


def encode_bcd(digits: str, length: int) -> bytes:
    """Pad 'digits' to 2*length digits and pack swapped nibbles."""
    digits = digits[: length * 2].ljust(length * 2, "F")
    out = bytearray()
    for i in range(0, len(digits), 2):
        lo = int(digits[i], 16)
        hi = int(digits[i + 1], 16)
        out.append((hi << 4) | lo)
    return bytes(out)


def h2b(s: str) -> bytes:
    """'3B9F95' -> b'\\x3b\\x9f\\x95'. Spaces tolerated."""
    return bytes.fromhex(s.replace(" ", ""))


def b2h(data: bytes) -> str:
    return data.hex().upper()


# ---------------------------------------------------------------- ICCID

def decode_iccid(data: bytes) -> str:
    return decode_bcd(data[:10])


def encode_iccid(iccid: str, length: int = 10) -> bytes:
    return encode_bcd(iccid[: 2 * length], length)


def iccid_luhn_ok(iccid: str) -> bool:
    """Check digit is the last digit (Luhn), as on ITU-T E.118."""
    digits = [int(c) for c in iccid if c.isdigit()]
    if len(digits) < 2:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


# ---------------------------------------------------------------- IMSI

def decode_imsi(data: bytes) -> str:
    """EF_IMSI (TS 31.102 / TS 24.008 mobile identity).

    [n bytes][flag digit][digits...]: the flag nibble (low nibble of the
    first payload byte) carries odd/even in bit 3 and identity type 001;
    the high nibble is the FIRST IMSI digit, then swapped BCD follows.
    """
    if len(data) < 2:
        return ""
    n_digits = (data[0] & 0x0F) * 2 - 1
    nibbles = [data[1] >> 4]
    for b in data[2:]:
        nibbles += [b & 0x0F, b >> 4]
    digits = nibbles[:n_digits]
    if not (data[1] & 0x08):  # even digit count: last nibble is padding
        digits = digits[:-1]
    return "".join(str(d) for d in digits).rstrip("F")


def encode_imsi(imsi: str) -> bytes:
    digits = "".join(c for c in imsi if c.isdigit())
    if len(digits) not in (14, 15, 16, 17, 18):
        raise ValueError(f"IMSI must be 14-18 digits, got {len(digits)}")
    flag = ((len(digits) & 1) << 3) | 0x1  # odd/even + type 'IMSI'
    h = f"{flag:01x}{digits}"
    if len(h) % 2:
        h += "F"
    payload = swap_nibbles(bytes.fromhex(h))
    return bytes([len(payload)]) + payload


# ---------------------------------------------------------------- PLMN

def decode_plmn(data: bytes) -> Optional[str]:
    """3 bytes -> 'MCC-MNC' (MNC 2 or 3 digits). None for FFFFFF (empty)."""
    if len(data) < 3:
        return None
    if data[:3] == b"\xff\xff\xff":
        return None
    # nibble order: MCC1 MCC2 MCC3 | MNC1 MNC2 MNC3
    d = [
        data[0] & 0x0F, data[0] >> 4,
        data[1] & 0x0F,
        data[2] & 0x0F, data[2] >> 4,
        data[1] >> 4,
    ]
    if any(x == PAD_NIBBLE for x in d[:3]):
        return None
    mcc = "".join(str(x) for x in d[:3])
    mnc_digits = [str(x) for x in d[3:] if x != PAD_NIBBLE]
    mnc = "".join(mnc_digits)
    if not mnc:
        return None
    return f"{mcc}-{mnc}"


def encode_plmn(plmn: str) -> bytes:
    mcc, mnc = plmn.split("-")
    if len(mcc) != 3 or len(mnc) not in (2, 3):
        raise ValueError(f"bad PLMN {plmn!r}, want 'MCC-MNC'")
    m1, m2, m3 = (int(c) for c in mcc)
    n = [int(c) for c in mnc] + [PAD_NIBBLE] * (3 - len(mnc))
    # byte0 = MCC2<<4 | MCC1, byte1 = MNC3<<4 | MCC3, byte2 = MNC2<<4 | MNC1
    return bytes([(m2 << 4) | m1, (n[2] << 4) | m3, (n[1] << 4) | n[0]])


def decode_plmn_list(data: bytes) -> List[str]:
    """Consecutive 3-byte PLMNs (FPLMN, EHPLMN...). FFFFFF entries skipped."""
    out = []
    for i in range(0, len(data) - 2, 3):
        p = decode_plmn(data[i : i + 3])
        if p:
            out.append(p)
    return out


def encode_plmn_list(plmns: List[str], entries: int) -> bytes:
    out = b""
    for i in range(entries):
        out += encode_plmn(plmns[i]) if i < len(plmns) else b"\xff\xff\xff"
    return out


# PLMN access technology list (PLMNwAcT / OPLMNwAcT / HPLMNwAcT records):
# each entry = 3-byte PLMN + 2-byte AcT bitmask. Bit assignments per
# TS 31.102 Table 4.2.5.1 (decoding mirrors pySim's dec_act).
def _acts_names(mask: int) -> List[str]:
    sel = []
    if mask & 0x8000:
        sel.append("UTRAN")
    if mask & 0x0800:
        sel.append("NG-RAN")
    if mask & 0x0040:
        sel.append("GSM COMPACT")
    if mask & 0x0020:
        sel.append("cdma2000 HRPD")
    if mask & 0x0010:
        sel.append("cdma2000 1xRTT")
    e = mask & 0x7000
    if e == 0x6000:
        sel.append("E-UTRAN WB-S1")
    elif e == 0x5000:
        sel.append("E-UTRAN NB-S1")
    elif e in (0x4000, 0x7000):
        sel += ["E-UTRAN WB-S1", "E-UTRAN NB-S1"]
    g = mask & 0x008C
    if g in (0x0084, 0x008C):
        sel.append("GSM")
    if g in (0x0088, 0x008C):
        sel.append("EC-GSM-IoT")
    return sel


def decode_plmn_w_act(data: bytes) -> List[Dict[str, object]]:
    out = []
    for i in range(0, len(data) - 4, 5):
        plmn = decode_plmn(data[i : i + 3])
        act = int.from_bytes(data[i + 3 : i + 5], "big")
        out.append({
            "plmn": plmn,
            "act_mask": act,
            "act": _acts_names(act),
            "raw": data[i : i + 5].hex().upper(),
        })
    return [e for e in out if e["plmn"]]


def encode_plmn_w_act(plmn: str, act_mask: int) -> bytes:
    return encode_plmn(plmn) + act_mask.to_bytes(2, "big")


# ---------------------------------------------------------------- numbers

TON_NPI = {
    "unknown": 0x00, "international": 0x91, "national": 0xA1,
    "network": 0x81, "subscriber": 0xA2, "abbreviated": 0xA3,
}


def encode_number(number: str, ton_npi: int = 0x91, max_bytes: int = 10) -> bytes:
    """'+' stripped; BCD body padded to max_bytes."""
    digits = number.replace("+", "").replace(" ", "")
    body = encode_bcd(digits, max_bytes)
    return bytes([ton_npi]) + body


def decode_number(data: bytes) -> Tuple[str, Optional[int]]:
    """(number, ton_npi). number gets '+' prefix for international TON."""
    if not data:
        return "", None
    ton_npi = data[0]
    digits = decode_bcd(data[1:])
    if (ton_npi >> 4) & 0x1 == 1:  # bit4 of high nibble = international
        digits = "+" + digits
    return digits, ton_npi


def decode_msisdn_record(record: bytes) -> Dict[str, object]:
    """EF_MSISDN / EF_ADN record layout (GSM 11.11 10.5.1):
    [alpha id][len of number][TON/NPI][BCD number up to 10 bytes].
    The number block occupies the last 12 bytes of the record.
    """
    if len(record) < 2 or all(b == 0xFF for b in record):
        return {"alpha": "", "number": "", "raw": b2h(record)}
    n = record[-12]  # length byte (number of digits, '+' not counted)
    number, ton_npi = decode_number(record[-11:])
    intl = number.startswith("+")
    digits = number[1:] if intl else number
    if n:
        digits = digits[:n]
    number = ("+" + digits) if intl else digits
    alpha = record[:-12]
    if alpha[:1] == b"\x80":
        alpha_text = alpha[1:].decode("utf-16-be", "ignore")
    else:
        alpha_text = alpha.decode("latin-1", "ignore")
    return {
        "alpha_raw": b2h(alpha),
        "alpha": alpha_text.rstrip("\xff\x00 ").strip(),
        "number": number,
        "ton_npi": f"{ton_npi:02X}" if ton_npi is not None else None,
    }


def encode_msisdn_record(number: str, alpha: bytes = b"",
                         record_len: int = 32) -> bytes:
    digits = number.replace("+", "")
    # layout: alpha (record_len-12) | len | TON/NPI + BCD body (11 bytes)
    body = bytes([len(digits)]) + encode_number(digits, 0x91, 10)
    out = alpha.ljust(record_len - 12, b"\xff") + body
    return out.ljust(record_len, b"\xff")[:record_len]


# ---------------------------------------------------------------- SMSP

def decode_smsp_record(record: bytes) -> Dict[str, object]:
    """EF_SMSP parameter set: [alpha][param-indicator][SCA 12B][rest...]."""
    if all(b == 0xFF for b in record) or len(record) < 20:
        return {"sca": "", "raw": b2h(record)}
    # SCA: 12 bytes BCD address with TON/NPI first byte (length byte absent)
    # followed by TP-SCTS(7), TP-VP(1), TP-DT(7)... locate SCA right after
    # the alpha/parameter indicator: param indicator is 1 byte when
    # bit8 of first byte... keep it simple: scan for the first byte with
    # high TON nibble that decodes to a plausible '+' number.
    for off in range(1, min(len(record) - 12, 24)):
        seg = record[off : off + 12]
        if seg[0] in (0x91, 0x81, 0xA1, 0xD1):
            digits = decode_bcd(seg[1:])
            if digits and seg[0] == 0x91:
                return {"sca": "+" + digits, "raw": b2h(record)}
            if digits:
                return {"sca": digits, "raw": b2h(record)}
    return {"sca": "", "raw": b2h(record)}


def encode_smsp_record(sca: str, record_len: int = 32,
                       alpha: bytes = b"") -> bytes:
    """Build a parameter set with only the SMSC address filled in.

    Parameter indicator 0x00 marks 'use defaults' for everything else.
    """
    digits = sca.replace("+", "")
    addr = encode_number(digits, 0x91, 11)  # 11 BCD bytes + TON/NPI = 12
    body = b"\x00" + addr[:12]
    out = alpha + body
    return out.ljust(record_len, b"\xff")[:record_len]


# ---------------------------------------------------------------- SPN

def decode_spn(data: bytes) -> Dict[str, object]:
    """EF_SPN: [display condition][name GSM-7 or UCS-2]."""
    if not data:
        return {"display_condition": None, "name": ""}
    cond = data[0]
    rest = data[1:].rstrip(b"\xff\x00 ")
    if rest[:1] == b"\x80":  # UCS-2 with 0x80 prefix
        name = rest[1:].decode("utf-16-be", "ignore")
    else:
        name = rest.decode("ascii", "ignore")
    return {
        "display_condition": cond,
        "show_in_mplmn": bool(cond & 0x01),
        "show_in_oplmn": bool(cond & 0x02),
        "name": name,
        "raw": b2h(data),
    }


def encode_spn(name: str, display_condition: int = 0x00) -> bytes:
    try:
        body = name.encode("ascii")
    except UnicodeEncodeError:
        body = b"\x80" + name.encode("utf-16-be")
    return bytes([display_condition]) + body.ljust(16, b"\xff")


# ---------------------------------------------------------------- misc EFs

def decode_gid(data: bytes) -> str:
    return b2h(data).rstrip("F") or ""


def decode_acc(data: bytes) -> Dict[str, object]:
    """EF_ACC: 2-byte access-control-class bitmask (cyclic file)."""
    val = int.from_bytes(data[:2], "big")
    classes = [i for i in range(1, 16) if val & (1 << i)]
    return {"value": b2h(data[:2]), "classes": classes}


def encode_acc(classes: List[int]) -> bytes:
    val = 0
    for c in classes:
        if 1 <= c <= 15:
            val |= 1 << c
    return val.to_bytes(2, "big")


def decode_ad(data: bytes) -> Dict[str, object]:
    """EF_AD: [len][MCC digits][MNC digits] (nibble swapped) + reserved."""
    if len(data) < 4 or data[0] == 0 or all(b == 0xFF for b in data):
        return {"raw": b2h(data)}
    ln = data[0]
    # actual layout: [len][MCC1MCC2][MCC3MNC1][MNC2(MNC3)] as plain nibbles
    nib = []
    for b in data[1:4]:
        nib += [b & 0x0F, b >> 4]
    mcc = f"{nib[0]}{nib[1]}{nib[2]}"
    mnc = "".join(str(x) for x in nib[3:] if x != PAD_NIBBLE)
    return {"len": ln, "mcc": mcc, "mnc": mnc, "raw": b2h(data)}


def encode_ad(mcc: str, mnc: str, extra: bytes = b"") -> bytes:
    nib = [int(c) for c in mcc] + [int(c) for c in mnc]
    nib += [PAD_NIBBLE] * (6 - len(nib))
    body = bytes([(nib[1] << 4) | nib[0], (nib[3] << 4) | nib[2], (nib[5] << 4) | nib[4]])
    ln = 4 if not extra else 4 + len(extra)
    return bytes([ln]) + body + extra


def decode_ecc_record(record: bytes) -> Dict[str, object]:
    """EF_ECC record: [len][3B BCD number][alpha id...]."""
    if len(record) < 4 or all(b == 0xFF for b in record):
        return {"number": "", "alpha": "", "raw": b2h(record)}
    ln = record[0]
    if ln == 0xFF:
        return {"number": "", "alpha": "", "raw": b2h(record)}
    number = decode_bcd(record[1:4]).rstrip("F") or ""
    alpha = record[4:].rstrip(b"\xff").decode("ascii", "ignore").strip()
    return {"number": number, "alpha": alpha, "raw": b2h(record)}


def decode_ust(data: bytes) -> List[int]:
    """EF_UST: 1-based service numbers that are available+enabled."""
    services = []
    for i, b in enumerate(data):
        for bit in range(8):
            if b & (1 << bit):
                services.append(i * 8 + bit + 1)
    return services


def decode_ehplmn(data: bytes) -> List[str]:
    return decode_plmn_list(data)


def decode_search_period(raw: bytes) -> Optional[int]:
    """EF_PLMNwAcT 'hplmn act' style helpers can live here if needed."""
    return int.from_bytes(raw, "big") if raw else None
