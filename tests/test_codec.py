"""Offline unit tests — no reader required. Run: python -m unittest discover -s tests"""

import unittest

from provisim import codec


class TestBcd(unittest.TestCase):
    def test_encode_decode_bcd(self):
        data = codec.encode_bcd("46000", 3)
        self.assertEqual(data.hex().upper(), "6400F0")
        self.assertEqual(codec.decode_bcd(data), "46000")

    def test_decode_strips_trailing_f(self):
        self.assertEqual(codec.decode_bcd(b"\x12\xf2"), "212")

    def test_invalid_nibble(self):
        with self.assertRaises(ValueError):
            codec.decode_bcd(b"\xab\xcd")  # a,b,c,d > 9 -> ValueError


class TestIccid(unittest.TestCase):
    def test_roundtrip(self):
        iccid = "89860112345678901234"  # 20 digits
        data = codec.encode_iccid(iccid, 10)
        self.assertEqual(codec.decode_iccid(data), iccid)

    def test_known_encoding(self):
        # first 6 digits 898600 -> 98 68 00
        self.assertEqual(codec.encode_iccid("8986001", 10)[:3].hex().upper(),
                         "986800")

    def test_luhn(self):
        self.assertTrue(codec.iccid_luhn_ok("89860112345678901237"))
        self.assertFalse(codec.iccid_luhn_ok("89860112345678901238"))


class TestImsi(unittest.TestCase):
    # synthetic 15-digit vector (structure taken from a real EF_IMSI capture;
    # digits replaced — do not commit live-card identifiers)
    REAL_CARD_VECTOR = bytes.fromhex("084906214365870921")

    def test_real_card_vector(self):
        self.assertEqual(codec.decode_imsi(self.REAL_CARD_VECTOR),
                         "460123456789012")
        self.assertEqual(codec.encode_imsi("460123456789012"),
                         self.REAL_CARD_VECTOR)

    def test_15_digit_roundtrip(self):
        imsi = "460010123456789"
        data = codec.encode_imsi(imsi)
        self.assertEqual(len(data), 9)          # 1 len byte + 8 payload bytes
        self.assertEqual(codec.decode_imsi(data), imsi)

    def test_18_digit_roundtrip(self):
        imsi = "460000000000000123"  # CN blank-card extension
        data = codec.encode_imsi(imsi)
        self.assertEqual(codec.decode_imsi(data), imsi)

    def test_length_byte(self):
        # 15-digit IMSI -> flag nibble + 15 digits = 8 payload bytes
        self.assertEqual(codec.encode_imsi("460010123456789")[0], 0x08)


class TestPlmn(unittest.TestCase):
    def test_china_mobile(self):
        self.assertEqual(codec.encode_plmn("460-00").hex().upper(), "64F000")
        self.assertEqual(codec.decode_plmn(bytes.fromhex("64F000")), "460-00")

    def test_three_digit_mnc(self):
        data = codec.encode_plmn("310-260")
        self.assertEqual(codec.decode_plmn(data), "310-260")
        # 310-410: oct1=MCC2|MCC1=0x13, oct2=MNC3|MCC3=0x00, oct3=MNC2|MNC1=0x14
        self.assertEqual(codec.encode_plmn("310-410").hex().upper(), "130014")

    def test_empty_plmn(self):
        self.assertIsNone(codec.decode_plmn(b"\xff\xff\xff"))

    def test_plmn_list(self):
        blob = codec.encode_plmn("460-00") + codec.encode_plmn("460-01") + b"\xff" * 3
        self.assertEqual(codec.decode_plmn_list(blob), ["460-00", "460-01"])

    def test_plmn_w_act(self):
        # E-UTRAN WB-S1 = 0x6000 per TS 31.102 Table 4.2.5.1
        blob = codec.encode_plmn_w_act("460-00", 0x6000)
        (entry,) = codec.decode_plmn_w_act(blob)
        self.assertEqual(entry["plmn"], "460-00")
        self.assertIn("E-UTRAN WB-S1", entry["act"])
        blob2 = codec.encode_plmn_w_act("460-00", 0x8084)  # UTRAN + GSM
        (e2,) = codec.decode_plmn_w_act(blob2)
        self.assertEqual(set(e2["act"]), {"UTRAN", "GSM"})


class TestNumbers(unittest.TestCase):
    def test_encode_decode_number(self):
        data = codec.encode_number("+8613800138000")
        num, ton = codec.decode_number(data)
        self.assertEqual(num, "+8613800138000")
        self.assertEqual(ton, 0x91)

    def test_msisdn_record_roundtrip(self):
        rec = codec.encode_msisdn_record("+8613800138000", alpha=b"TEST")
        parsed = codec.decode_msisdn_record(rec)
        self.assertEqual(parsed["number"], "+8613800138000")
        self.assertEqual(parsed["alpha"], "TEST")

    def test_empty_record(self):
        parsed = codec.decode_msisdn_record(b"\xff" * 32)
        self.assertEqual(parsed["number"], "")


class TestSmsp(unittest.TestCase):
    def test_roundtrip(self):
        rec = codec.encode_smsp_record("+687770009")  # value from GUI default
        self.assertEqual(codec.decode_smsp_record(rec)["sca"], "+687770009")

    def test_empty(self):
        self.assertEqual(codec.decode_smsp_record(b"\xff" * 32)["sca"], "")


class TestSpn(unittest.TestCase):
    def test_roundtrip(self):
        data = codec.encode_spn("China Mobile", display_condition=0x01)
        parsed = codec.decode_spn(data)
        self.assertEqual(parsed["name"], "China Mobile")
        self.assertTrue(parsed["show_in_mplmn"])
        self.assertFalse(parsed["show_in_oplmn"])

    def test_raw_16_byte_fill(self):
        data = codec.encode_spn("CMCC")
        self.assertEqual(len(data), 17)


class TestMisc(unittest.TestCase):
    def test_acc(self):
        data = codec.encode_acc([2, 5])
        self.assertEqual(data.hex().upper(), "0024")
        self.assertEqual(codec.decode_acc(data)["classes"], [2, 5])

    def test_ad_roundtrip(self):
        data = codec.encode_ad("460", "00")
        parsed = codec.decode_ad(data)
        self.assertEqual((parsed["mcc"], parsed["mnc"]), ("460", "00"))

    def test_ecc_record(self):
        # [len][3B bcd number][alpha]; '112' -> 11 F2 FF
        rec = bytes([3]) + bytes([0x11, 0xF2, 0xFF]) + b"Police" + b"\xff" * 8
        parsed = codec.decode_ecc_record(rec.ljust(20, b"\xff"))
        self.assertEqual(parsed["number"], "112")
        self.assertEqual(parsed["alpha"], "Police")

    def test_ust(self):
        self.assertEqual(codec.decode_ust(b"\x38"), [4, 5, 6])

    def test_gid(self):
        self.assertEqual(codec.decode_gid(b"\x54\x50\xff\xff"), "5450")


if __name__ == "__main__":
    unittest.main()
