"""PC/SC reader transport.

Equivalent of ICC_OpenReader / ICC_CloseReader / ICC_ResetCard in ICCAPI.dll.
Works with any CCID reader (the bundled Realtek reader uses the standard
Windows USBCCID class driver; the vendor RtsUCcid driver is optional).
"""

from __future__ import annotations

from typing import Callable, List, Optional

from .apdu import CardError

try:
    from smartcard.System import readers
    from smartcard.Exceptions import (CardConnectionException,
                                      NoReadersException, SmartcardException)
    from smartcard.CardConnection import CardConnection
except ImportError as exc:  # pragma: no cover
    raise ImportError("pyscard is required: pip install pyscard") from exc


class ReaderNotFoundError(Exception):
    pass


def list_readers() -> List[str]:
    """Return names of all PC/SC readers present."""
    try:
        return [str(r) for r in readers()]
    except NoReadersException:
        return []


class PcscTransport:
    """Owns one reader connection; use as a context manager.

    >>> with PcscTransport() as t:            # first reader
    ...     ...
    >>> with PcscTransport("Realtek USB Smart Card reader 0") as t:
    ...     ...
    """

    def __init__(self, reader_name: Optional[str] = None,
                 protocol: str = CardConnection.T1_protocol):
        self.reader_name = reader_name
        self.protocol = protocol
        self._conn: Optional[CardConnection] = None
        self.atr: bytes = b""
        # Negotiated protocol of the connected card ('T=0' or 'T=1')
        self.active_protocol: Optional[str] = None
        # Optional APDU logger (e.g. print) — handy when reverse engineering
        # vendor tool sequences against the same reader.
        self.log: Optional[Callable[[str], None]] = None

    # -- lifecycle ----------------------------------------------------

    def __enter__(self) -> "PcscTransport":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.disconnect()

    def connect(self) -> None:
        found = list_readers()
        if not found:
            raise ReaderNotFoundError(
                "No PC/SC readers found. Plug in the reader; the Windows "
                "Smart Card service (SCardSvr) must be running.")
        if self.reader_name is None:
            self.reader_name = found[0]
        elif self.reader_name not in found:
            # allow a unique prefix / substring match
            matches = [n for n in found if self.reader_name.lower() in n.lower()]
            if len(matches) != 1:
                raise ReaderNotFoundError(
                    f"Reader {self.reader_name!r} not in {found}")
            self.reader_name = matches[0]
        for r in readers():
            if str(r) == self.reader_name:
                self._conn = r.createConnection()
                break
        # Try the preferred protocol first, then the other (classic GSM SIMs
        # are usually T=0, USIMs T=1).
        candidates = [self.protocol, CardConnection.T0_protocol, CardConnection.T1_protocol]
        last_err = None
        for proto in dict.fromkeys(candidates):  # unique, keep order
            try:
                self._conn.connect(proto)
                self.active_protocol = proto
                self.protocol = proto
                break
            except CardConnectionException as e:
                last_err = e
        else:
            raise last_err
        self.atr = bytes(self._conn.getATR())

    def disconnect(self) -> None:
        if self._conn is not None:
            try:
                self._conn.disconnect()
            finally:
                self._conn = None

    def reset(self) -> bytes:
        """ICC_ResetCard: reconnect and return the new ATR."""
        if self._conn is None:
            raise RuntimeError("not connected")
        self._conn.disconnect()
        self._conn.connect(self.protocol)
        self.atr = bytes(self._conn.getATR())
        return self.atr

    # -- raw exchange ---------------------------------------------------

    def transmit(self, cla: int, ins: int, p1: int, p2: int,
                 data: bytes = b"", le: Optional[int] = None):
        """Send one raw APDU. Returns (response_bytes, sw1, sw2)."""
        if self._conn is None:
            raise RuntimeError("not connected")
        cmd = bytes([cla, ins, p1, p2])
        if data:
            if len(data) > 255:
                raise ValueError("extended Lc not supported")
            cmd += bytes([len(data)]) + data
        if le is not None:
            cmd += bytes([le if le < 256 else 0])
        try:
            resp, sw1, sw2 = self._conn.transmit(list(cmd))
        except SmartcardException as e:
            raise CardError(0x00, 0x00, f"reader I/O failure: {e}") from e
        return bytes(resp), sw1, sw2
