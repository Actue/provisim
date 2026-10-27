"""FCP template parsing."""

import unittest

from provisim.card import Fcp, FileStructure, parse_fcp
from provisim.files import lookup_ef


class TestFcp(unittest.TestCase):
    def test_transparent_ef(self):
        # FCP for a transparent EF: size 0x0009, FID 6F07, SFI 07
        data = bytes.fromhex(
            "62 1E 82 02 41 21 83 02 6F 07 8A 01 05 80 02 00 09 88 01 07")
        fcp = parse_fcp(data)
        self.assertEqual(fcp.fid, "6F07")
        self.assertEqual(fcp.size, 9)
        self.assertEqual(fcp.sfi, 7)
        self.assertEqual(fcp.structure, FileStructure.TRANSPARENT)
        self.assertEqual(fcp.lifecycle, "operational-active")

    def test_linear_fixed_ef(self):
        # FD bytes: 42 21 00 20 0A -> linear fixed, rec len 0x0020, count 0x0A
        # (descriptor layout per TS 102 221 11.1.1.4.3, as in pySim vectors)
        data = bytes.fromhex(
            "62 15 82 05 42 21 00 20 0A 83 02 6F 42 8A 01 05 "
            "80 02 01 00 88 01 06")
        fcp = parse_fcp(data)
        self.assertEqual(fcp.structure, FileStructure.LINEAR_FIXED)
        self.assertEqual(fcp.record_len, 32)
        self.assertEqual(fcp.record_count, 10)
        self.assertTrue(fcp.record_based)

    def test_adf_fcp_df_name(self):
        data = bytes.fromhex(
            "62 1C 82 05 42 21 00 0A 05 83 02 3F 00 84 10 "
            "A0 00 00 00 87 10 02 FF 86 FF 03 89 FF FF FF FF")
        fcp = parse_fcp(data)
        self.assertEqual(fcp.df_name[:16], "A0000000871002FF")
        self.assertEqual(fcp.fid, "3F00")

    def test_garbage_tolerated(self):
        fcp = parse_fcp(b"\x3f\x00\x00")
        self.assertEqual(fcp.size, None)


class TestEfTable(unittest.TestCase):
    def test_lookup_qualified(self):
        d = lookup_ef("IMSI")
        self.assertEqual(d.fid, "6F07")
        self.assertEqual(d.parent.name, "ADF_USIM")

    def test_lookup_scoped(self):
        d = lookup_ef("IMSI", None)
        # unscoped resolves to the single candidate after scoping default
        d2 = lookup_ef("SPN")
        self.assertIn(d2.parent.name, ("ADF_USIM",))

    def test_unknown(self):
        with self.assertRaises(KeyError):
            lookup_ef("NO_SUCH_EF")


if __name__ == "__main__":
    unittest.main()
