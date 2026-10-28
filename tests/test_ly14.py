"""Ly14Card private-command construction tests (offline).

Every expected byte sequence is copied verbatim from the strings embedded
in GRSIMWrite.exe's CODE section (see C:/tmp/re_grsim/placeholders.txt).
"""

import unittest

from provisim.codec import h2b
from provisim.ly14 import Ly14Card, FB_MAGIC, FB_MAGIC_OPC_HEAD
from tests.test_apdu import FakeTransport

KI = "79250CFA46E99A0C2548CD89135DA53E"  # sample Ki from the binary itself
OPC = "11111111111111111111111111111111"


class Ly14Fake(FakeTransport):
    """Answers any command with 9000, records everything."""

    def __init__(self):
        super().__init__([])
        self.sent = []
        self.log = None

    def transmit(self, cla, ins, p1, p2, data=b"", le=None):
        cmd = bytes([cla, ins, p1, p2])
        if data:
            cmd += bytes([len(data)]) + data
        if le is not None:
            cmd += bytes([le if le < 256 else 0])
        self.sent.append(cmd)
        return b"", 0x90, 0x00


def make_card():
    t = Ly14Fake()
    t.atr = b"\x3b\x9f"
    return Ly14Card(t), t


class TestGen4(unittest.TestCase):
    def test_fb_pin1(self):
        card, t = make_card()
        card.fb_write("PIN1", "1234")
        self.assertEqual(t.sent[0], bytes.fromhex(
            "A0FB000010" + FB_MAGIC["PIN1"] + "31323334FFFFFFFF"))

    def test_fb_ki(self):
        card, t = make_card()
        card.fb_write("LTE_KI", KI)
        self.assertEqual(t.sent[0],
                         bytes.fromhex("A0FB000018" + FB_MAGIC["LTE_KI"] + KI))

    def test_fb_opc(self):
        card, t = make_card()
        card.fb_write("LTE_OPC", OPC)
        self.assertEqual(
            t.sent[0], bytes.fromhex("A0FB001019" + FB_MAGIC_OPC_HEAD + OPC))

    def test_fb_unlock_sadm(self):
        card, t = make_card()
        card.fb_unlock_sadm("3838383838383838")
        self.assertEqual(t.sent[0],
                         bytes.fromhex("A0FBFFFF08" + "3838383838383838"))


class TestDispatch(unittest.TestCase):
    def test_7ff0_path(self):
        # all probes succeed (9000) -> 7FF0 branch wins; Ki is mirrored
        # into EFs 0006/000F/0012 like the vendor GUI does
        card, t = make_card()
        card.set_ki(KI)
        self.assertIn(bytes.fromhex("A0A40804043F007FF0"), t.sent)
        for ef in ("0006", "000F", "0012"):
            self.assertIn(bytes.fromhex(f"A0A4000402{ef}"), t.sent)
            self.assertIn(bytes.fromhex("A0D6000110" + KI), t.sent)
        # last command writes the final mirror EF
        self.assertEqual(t.sent[-1], bytes.fromhex("A0D6000110" + KI))

    def test_gen3_fallback(self):
        # make every probe fail by answering 6D00, except nothing succeeds
        class FailAll(Ly14Fake):
            # probes (INS 92/96/A4) fail -> no generation detected,
            # but the gen3 write commands (D4/D5) succeed
            def transmit(self, cla, ins, p1, p2, data=b"", le=None):
                cmd = super().transmit(cla, ins, p1, p2, data, le)
                if ins in (0x92, 0x96, 0xA4):
                    return b"", 0x6D, 0x00
                return b"", 0x90, 0x00

        t = FailAll()
        t.atr = b"\x3b"
        card = Ly14Card(t)
        card.set_ki(KI)
        self.assertEqual(t.sent[-1], bytes.fromhex("00D51C0010" + KI))
        card.set_opc(OPC)
        self.assertEqual(t.sent[-1], bytes.fromhex("00D5015710" + OPC))


class TestAdm(unittest.TestCase):
    def test_verify_adm_hex(self):
        card, t = make_card()
        card.verify_adm("3838383838383838", ref=0x0B)
        self.assertEqual(t.sent[0],
                         bytes.fromhex("A020000B083838383838383838"))

    def test_verify_adm_ascii(self):
        card, t = make_card()
        card.verify_adm("88888888", ref=0x0B)
        self.assertEqual(t.sent[0],
                         bytes.fromhex("A020000B083838383838383838"))


class TestTemplates(unittest.TestCase):
    def test_template_load_and_dry_run(self):
        from provisim.ly14_templates import TEMPLATES
        self.assertEqual(len(TEMPLATES), 13)
        card, t = make_card()
        ops = card.replay_template(0, dry_run=True)
        self.assertEqual(len(ops), 58)
        self.assertIn("A053000000", ops[-1])
        # nothing sent in dry run
        self.assertEqual(t.sent, [])

    def test_pin_substitution(self):
        card, _ = make_card()
        ops = card.replay_template(0, dry_run=True, pin="99998888")
        self.assertTrue(any("3939393938383838" in op for op in ops))

    def test_placeholder_substitution(self):
        card, _ = make_card()
        out = Ly14Card._substitute("A0D6000110[LTE_KI]",
                                   {"LTE_KI": KI})
        self.assertEqual(out, "A0D6000110" + KI)


if __name__ == "__main__":
    unittest.main()
