"""Command APDU construction and status-word handling.

Mirrors ICC_ExecComm() from ICCAPI.dll but with automatic handling of
61xx (GET RESPONSE), 6Cxx (wrong Le) and PIN retry counters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

# Common status words (ISO 7816-4 + GSM 11.11)
SW_DESCRIPTIONS = {
    0x9000: "OK",
    0x6700: "Wrong length",
    0x6982: "Security status not satisfied (PIN/ADM not verified)",
    0x6985: "Command not allowed (write protected?)",
    0x6A82: "File / application not found",
    0x6A86: "Incorrect P1-P2",
    0x6A87: "Lc inconsistent with P1-P2",
    0x6D00: "Instruction not supported",
    0x6E00: "Class not supported",
    0x9400: "No EF selected",
    0x9402: "Out of range (record number / address)",
    0x9404: "File ID / pattern not found",
    0x9408: "File inconsistent with command",
    0x9840: "PIN verification failed / CHV blocked",
    0x9850: "CHV cannot be changed / invalidated",
}


class CardError(Exception):
    """Response SW != 9000 that could not be handled automatically."""

    def __init__(self, sw1: int, sw2: int, context: str = ""):
        self.sw1 = sw1
        self.sw2 = sw2
        self.sw = (sw1 << 8) | sw2
        self.context = context
        desc = SW_DESCRIPTIONS.get(self.sw, "")
        if sw1 == 0x63 and sw2 & 0xF0 == 0xC0:
            desc = f"verification failed, {sw2 & 0x0F} retries left"
        msg = f"SW={sw1:02X}{sw2:02X}"
        if desc:
            msg += f" ({desc})"
        if context:
            msg += f" [{context}]"
        super().__init__(msg)


class PinRetryError(CardError):
    """PIN/ADM verification failure; carries the remaining retry counter."""

    def __init__(self, sw1: int, sw2: int, context: str = ""):
        self.retries_left = sw2 & 0x0F
        super().__init__(sw1, sw2, context)


@dataclass
class Apdu:
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes = field(default_factory=b"")
    le: Optional[int] = None

    def to_bytes(self) -> bytes:
        out = bytes([self.cla, self.ins, self.p1, self.p2])
        if self.data:
            out += bytes([len(self.data)]) + self.data
        if self.le is not None:
            out += bytes([self.le if self.le < 256 else 0])
        return out

    def __str__(self) -> str:
        s = self.to_bytes().hex().upper()
        return " ".join(s[i : i + 2] for i in range(0, len(s), 2))


def make_apdu(cla: int, ins: int, p1: int, p2: int,
              data: bytes = b"", le: Optional[int] = None) -> Apdu:
    return Apdu(cla, ins, p1, p2, data, le)


def exchange(transport, cla: int, ins: int, p1: int, p2: int,
             data: bytes = b"", le: Optional[int] = None,
             context: str = "", log: Optional[Callable[[str], None]] = None) -> bytes:
    """Send one command, follow 61xx/6Cxx chains, raise on hard errors.

    Returns the response data (SW stripped).
    """
    resp, sw1, sw2 = transport.transmit(cla, ins, p1, p2, data, le)
    if log:
        log(f"> {cla:02X} {ins:02X} {p1:02X} {p2:02X} {data.hex().upper()} "
            f"< {resp.hex().upper()} {sw1:02X}{sw2:02X}")

    # Wrong Le: card tells us the right one, re-issue.
    if sw1 == 0x6C:
        resp, sw1, sw2 = transport.transmit(cla, ins, p1, p2, data, sw2)
    # More data available: GET RESPONSE loop.
    while sw1 == 0x61:
        take = sw2 if sw2 else 256
        more, sw1, sw2 = transport.transmit(cla, 0xC0, 0x00, 0x00, b"", take)
        resp += more
        if log:
            log(f"> {cla:02X} C0 00 00 {take:02X} < {more.hex().upper()} {sw1:02X}{sw2:02X}")

    if sw1 == 0x90 and sw2 == 0x00:
        return resp
    if sw1 == 0x63 and sw2 & 0xF0 == 0xC0:
        raise PinRetryError(sw1, sw2, context)
    raise CardError(sw1, sw2, context)
