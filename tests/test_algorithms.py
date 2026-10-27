"""Milenage + AES unit tests against public reference vectors.

Sources:
  * AES-128: FIPS-197 Appendix C.1
  * f2345 / compute_opc: 3GPP TS 35.208 test set 2 (as cited by the Rust
    `milenage` crate docs)
  * f1*/f5*: libosmocore tests/auth/milenage_test.c (TS 33.102 6.3.3 AUTS)
"""

import unittest

from provisim import algorithms as alg
from provisim.codec import h2b


class TestAes(unittest.TestCase):
    def test_fips197_vector(self):
        # FIPS-197 Appendix C.1 (AES-128)
        key = h2b("000102030405060708090A0B0C0D0E0F")
        block = h2b("00112233445566778899AABBCCDDEEFF")
        expected = h2b("69C4E0D86A7B0430D8CDB78070B4C55A")
        self.assertEqual(alg.aes128_encrypt_block(key, block), expected)


class TestMilenageSet2(unittest.TestCase):
    """3GPP TS 35.208 test set 2 — exercises compute_opc + f2345."""

    K = h2b("465B5CE8B199B49FAA5F0A2EE238A6BC")
    OP = h2b("CDC202D5123E20F62B6D676AC72CB318")
    RAND = h2b("23553CBE9637A89D218AE64DAE47BF35")

    RES = h2b("A54211D5E3BA50BF")
    CK = h2b("B40BA9A3C58B2A05BBF0D987B21BF8CB")
    IK = h2b("F769BCD751044604127672711C6D3441")
    AK = h2b("AA689C648370")

    def test_f2345(self):
        opc = alg.compute_opc(self.K, self.OP)
        out = alg.milenage_f2345(self.K, opc, self.RAND)
        self.assertEqual(out["RES"], self.RES)
        self.assertEqual(out["CK"], self.CK)
        self.assertEqual(out["IK"], self.IK)
        self.assertEqual(out["AK"], self.AK)


class TestMilenageOsmocom(unittest.TestCase):
    """libosmocore milenage_test.c — exercises f1star + f5star."""

    K = h2b("000102030405060708090A0B0C0D0E0F")
    OPC = h2b("000102030405060708090A0B0C0D0E0F")
    RAND = h2b("00000000000000000000000000000000")
    SQN_MS = h2b("00000000001F")
    AMF = h2b("0000")

    AK_STAR = h2b("8711A0EC9E09")
    MAC_S = h2b("37DF17F80B384EE4")

    def test_f5star(self):
        self.assertEqual(
            alg.milenage_f5star(self.K, self.OPC, self.RAND), self.AK_STAR)

    def test_f1star(self):
        self.assertEqual(
            alg.milenage_f1star(self.K, self.OPC, self.RAND,
                                self.SQN_MS, self.AMF), self.MAC_S)

    def test_f1_runs_and_differs_from_f1star(self):
        # f1 shares OUT1 with f1*: different halves, so different values
        mac_a = alg.milenage_f1(self.K, self.OPC, self.RAND, self.SQN_MS, self.AMF)
        self.assertEqual(len(mac_a), 8)
        self.assertNotEqual(mac_a, self.MAC_S)


if __name__ == "__main__":
    unittest.main()
