"""provisim — Python library for SIM/USIM card access via PC/SC readers.

Replaces the GRSIMWrite GUI + ICCAPI/MIDLL stack:

- transport: reader discovery and APDU exchange (PC/SC via pyscard)
- apdu: command APDU construction and status-word handling
- card: UICC file system navigation (SELECT, READ/UPDATE BINARY/RECORD, PIN/ADM)
- codec: encode/decode of EF payloads (ICCID, IMSI, PLMN, SMSP, SPN, ...)
- files: EF directory table (GSM 11.11 / 3GPP TS 31.102 / 31.103)
- profile: high-level read_card() / write_card()
- algorithms: host-side Milenage (f1..f5, OPc), mirroring MIDLL.dll
- ly14: private APDUs of the blank "LY14" programmable card (RE pending)
"""

__version__ = "0.1.0"

from .apdu import Apdu, CardError, PinRetryError, make_apdu
from .transport import PcscTransport, list_readers
from .card import UiccCard, Fcp, FileStructure

__all__ = [
    "Apdu",
    "CardError",
    "PinRetryError",
    "make_apdu",
    "PcscTransport",
    "list_readers",
    "UiccCard",
    "Fcp",
    "FileStructure",
]
