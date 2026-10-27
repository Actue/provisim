"""Milenage (TS 35.205/35.206) — pure-Python, mirrors MIDLL.dll exports.

MIDLL.dll exports: f1, f1star, f2345, f5star, ComputeOPc, Rijndael*.
Here: milenage_f1(), milenage_f1star(), milenage_f2345(), milenage_f5star(),
compute_opc(). AES-128 block encryption is implemented inline (validated
against the FIPS-197 vector in tests) so this module has no dependencies.
"""

from __future__ import annotations

from typing import Dict

# --------------------------------------------------------------- AES-128

# Standard AES S-box (FIPS-197). Hardcoded rather than generated to keep
# this table verifiable against the spec text.
SBOX = bytes.fromhex(
    "637C777BF26B6FC53001672BFED7AB76"
    "CA82C97DFA5947F0ADD4A2AF9CA472C0"
    "B7FD9326363FF7CC34A5E5F171D83115"
    "04C723C31896059A071280E2EB27B275"
    "09832C1A1B6E5AA0523BD6B329E32F84"
    "53D100ED20FCB15B6ACBBE394A4C58CF"
    "D0EFAAFB434D338545F9027F503C9FA8"
    "51A3408F929D38F5BCB6DA2110FFF3D2"
    "CD0C13EC5F974417C4A77E3D645D1973"
    "60814FDC222A908846EEB814DE5E0BDB"
    "E0323A0A4906245CC2D3AC629195E479"
    "E7C8376D8DD54EA96C56F4EA657AAE08"
    "BA78252E1CA6B4C6E8DD741F4BBD8B8A"
    "703EB5664803F60E613557B986C11D9E"
    "E1F8981169D98E949B1E87E9CE5528DF"
    "8CA1890DBFE6426841992D0FB054BB16"
)
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x1B) & 0xFF if a & 0x100 else a


def aes128_key_schedule(key: bytes) -> list:
    assert len(key) == 16
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [SBOX[b] for b in t]
            t[0] ^= RCON[i // 4 - 1]
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [[b for i in range(4 * r, 4 * r + 4) for b in w[i]]
            for r in range(11)]


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """AES-128 single-block encryption (ECB of one block)."""
    rk = aes128_key_schedule(key)

    def add_rk(s, r):
        return [a ^ b for a, b in zip(s, rk[r])]

    def sub_shift(s):
        # SubBytes + ShiftRows. Flat state is column-major: s[col*4 + row].
        # ShiftRows: new[r][c] = SBOX[old[r][(c + r) % 4]]
        s2 = [0] * 16
        for r in range(4):
            for c in range(4):
                s2[c * 4 + r] = SBOX[s[((c + r) % 4) * 4 + r]]
        return s2

    def mix(s):
        out = [0] * 16
        for c in range(4):
            a = s[c*4:c*4+4]
            out[c*4 + 0] = _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3]
            out[c*4 + 1] = a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3]
            out[c*4 + 2] = a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3])
            out[c*4 + 3] = (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3])
        return out

    s = add_rk(list(block), 0)
    for rnd in range(1, 10):
        s = sub_shift(s)
        s = mix(s)
        s = add_rk(s, rnd)
    s = sub_shift(s)
    s = add_rk(s, 10)
    return bytes(s)


# --------------------------------------------------------------- Milenage

C1 = bytes(16)
C2 = bytes(15) + b"\x01"
C3 = bytes(15) + b"\x02"
C4 = bytes(15) + b"\x04"
C5 = bytes(15) + b"\x08"
R1, R2, R3, R4, R5 = 64, 0, 32, 64, 96  # rotation, bits


def _rot_left(data: bytes, bits: int) -> bytes:
    n = bits // 8
    return data[n:] + data[:n] if bits % 8 == 0 else _rot_bits(data, bits)


def _rot_bits(data: bytes, bits: int) -> bytes:
    as_int = int.from_bytes(data, "big")
    width = len(data) * 8
    as_int = ((as_int << bits) | (as_int >> (width - bits))) & ((1 << width) - 1)
    return as_int.to_bytes(len(data), "big")


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def compute_opc(k: bytes, op: bytes) -> bytes:
    """TS 35.206 §4.1: OPC = OP xor E[OP]_K (single step)."""
    return _xor(op, aes128_encrypt_block(k, op))


def _in1(sqn: bytes, amf: bytes) -> bytes:
    assert len(sqn) == 6 and len(amf) == 2
    return sqn + amf + sqn + amf


def _temp(k: bytes, opc: bytes, rand: bytes) -> bytes:
    return aes128_encrypt_block(k, _xor(rand, opc))


def milenage_f1(k: bytes, opc: bytes, rand: bytes,
                sqn: bytes, amf: bytes) -> bytes:
    """Returns MAC-A (8 bytes).

    OUT1 = E[TEMP ⊕ rot(IN1 ⊕ OPc, r1) ⊕ c1]_K ⊕ OPc; MAC-A = OUT1[0..63].
    """
    temp = _temp(k, opc, rand)
    blk = _xor(temp, _xor(_rot_left(_xor(_in1(sqn, amf), opc), R1), C1))
    out1 = _xor(aes128_encrypt_block(k, blk), opc)
    return out1[:8]


def milenage_f1star(k: bytes, opc: bytes, rand: bytes,
                    sqn: bytes, amf: bytes) -> bytes:
    """Returns MAC-S (8 bytes) = OUT1[64..127]."""
    temp = _temp(k, opc, rand)
    blk = _xor(temp, _xor(_rot_left(_xor(_in1(sqn, amf), opc), R1), C1))
    out1 = _xor(aes128_encrypt_block(k, blk), opc)
    return out1[8:]


def milenage_f2345(k: bytes, opc: bytes, rand: bytes) -> Dict[str, bytes]:
    """Returns RES, CK, IK, AK.

    OUT2 = E[rot(TEMP ⊕ OPc, r2) ⊕ c2]_K ⊕ OPc with RES = OUT2[64..127],
    AK = OUT2[0..47]; CK = OUT3; IK = OUT4 (same shape with c3/r3, c4/r4).
    """
    base = _xor(_temp(k, opc, rand), opc)
    out2 = _xor(aes128_encrypt_block(k, _xor(_rot_left(base, R2), C2)), opc)
    out3 = _xor(aes128_encrypt_block(k, _xor(_rot_left(base, R3), C3)), opc)
    out4 = _xor(aes128_encrypt_block(k, _xor(_rot_left(base, R4), C4)), opc)
    return {"RES": out2[8:], "AK": out2[:6], "CK": out3, "IK": out4}


def milenage_f5star(k: bytes, opc: bytes, rand: bytes) -> bytes:
    """Returns AK' (6 bytes) = OUT5[0..47]."""
    base = _xor(_temp(k, opc, rand), opc)
    out5 = _xor(aes128_encrypt_block(k, _xor(_rot_left(base, R5), C5)), opc)
    return out5[:6]


def autn(sqn: bytes, ak: bytes, amf: bytes, mac_a: bytes) -> bytes:
    """AUTN = SQN xor AK || AMF || MAC-A."""
    return bytes(a ^ b for a, b in zip(sqn, ak)) + amf + mac_a
