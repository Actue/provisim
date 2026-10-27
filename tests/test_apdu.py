"""APDU exchange logic against a fake transport."""

import unittest

from provisim.apdu import Apdu, CardError, PinRetryError, exchange


class FakeTransport:
    def __init__(self, script):
        # script: list of (apdu_bytes -> (resp, sw1, sw2))
        self.script = script
        self.sent = []

    def transmit(self, cla, ins, p1, p2, data=b"", le=None):
        cmd = bytes([cla, ins, p1, p2])
        if data:
            cmd += bytes([len(data)]) + data
        if le is not None:
            cmd += bytes([le if le < 256 else 0])
        self.sent.append(cmd)
        for pattern, (resp, sw1, sw2) in self.script:
            if pattern == cmd:
                self.script.remove((pattern, (resp, sw1, sw2)))
                return resp, sw1, sw2
        raise AssertionError(f"unexpected APDU: {cmd.hex()}")


class TestApdu(unittest.TestCase):
    def test_ok(self):
        t = FakeTransport([(bytes.fromhex("00A40404"), (b"resp", 0x90, 0x00))])
        out = exchange(t, 0x00, 0xA4, 0x04, 0x04)
        self.assertEqual(out, b"resp")

    def test_61xx_get_response(self):
        t = FakeTransport([
            (bytes.fromhex("00B00000FF"), (b"", 0x61, 0x04)),
            (bytes.fromhex("00C0000004"), (b"abcd", 0x90, 0x00)),
        ])
        out = exchange(t, 0x00, 0xB0, 0x00, 0x00, le=0xFF)
        self.assertEqual(out, b"abcd")

    def test_6cxx_wrong_le(self):
        t = FakeTransport([
            (bytes.fromhex("00B00000FF"), (b"", 0x6C, 0x10)),
            (bytes.fromhex("00B0000010"), (b"0123456789ABCDEF", 0x90, 0x00)),
        ])
        out = exchange(t, 0x00, 0xB0, 0x00, 0x00, le=0xFF)
        self.assertEqual(out, b"0123456789ABCDEF")

    def test_63cx_pin_retry(self):
        t = FakeTransport([(bytes.fromhex("00200008"), (b"", 0x63, 0xC2))])
        with self.assertRaises(PinRetryError) as ctx:
            exchange(t, 0x00, 0x20, 0x00, 0x08)
        self.assertEqual(ctx.exception.retries_left, 2)

    def test_hard_error(self):
        t = FakeTransport([(bytes.fromhex("00A40404"), (b"", 0x6A, 0x82))])
        with self.assertRaises(CardError):
            exchange(t, 0x00, 0xA4, 0x04, 0x04)

    def test_apdu_str(self):
        a = Apdu(0x00, 0xA4, 0x04, 0x04, b"\xA0\x00", le=0)
        self.assertEqual(str(a), "00 A4 04 04 02 A0 00 00")


if __name__ == "__main__":
    unittest.main()
