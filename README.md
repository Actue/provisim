# provisim

**Provision SIM/USIM cards from Python** — a clean, scriptable replacement
for vendor SIM-personalization GUIs (GRSIMWrite & friends), built on
PC/SC (`pyscard`).

- 📖 read full card profiles (ICCID, IMSI, ACC, PLMN lists, SPN, MSISDN, …) as JSON
- ✍️  write card fields with a dry-run-first API (ADM required)
- 🔓 reverse-engineered private protocols for **blank programmable cards**
  (LY14 / Watchdata family, four protocol generations) — write **Ki / OPc /
  algorithm / PINs** to writable cards, replay full initialisation templates
- 🔐 host-side **Milenage** (f1–f5\*, OPc) verified against 3GPP test vectors
- 🖥️ CLI + library, zero dependencies beyond pyscard, works with any CCID reader

Works with any standard CCID smart-card reader (the Realtek readers bundled
with Chinese SIM-writer kits run on Windows' built-in USBCCID class driver).

## Install

```powershell
pip install .          # from a checkout
provisim readers       # console script (or: python -m provisim readers)
```

## CLI

```text
provisim readers                          # list PC/SC readers
provisim info                             # ATR, apps, ICCID, IMSI
provisim read -o card.json                # full profile -> JSON
provisim dump-ef IMSI                     # raw hex of one EF
provisim apdu "00A40804023F002FE2"        # send a raw APDU (RE aid)
provisim pin verify --ref 0x08 --value <ADM>
provisim write -i card.json --adm <ADM>   # dry run; add --yes to apply
```

Blank programmable card (LY14 family):

```python
from provisim import PcscTransport
from provisim.ly14 import Ly14Card

with PcscTransport() as t:
    card = Ly14Card(t)
    print(card.probe())          # read-only: which protocol generation?
    card.verify_adm("3838383838383838")            # factory ADM '88888888'
    card.set_ki("00112233445566778899aabbccddeeff")
    card.set_opc("11111111111111111111111111111111")
    print(card.read_ki().hex())  # some generations allow Ki readback
```

## Library layout

| module | role |
|---|---|
| `transport` | PC/SC reader connection, T=0/T=1 auto-negotiation, APDU log hook |
| `apdu` | APDU exchange: 61xx/6Cxx handling, PIN retry counters |
| `card` | UICC file system: SELECT (AID/path/FID), FCP parsing, BINARY/RECORD read/write, PIN/ADM |
| `codec` | EF payload codecs (ICCID, IMSI, PLMN+AcT, MSISDN, SMSP, SPN, ACC, AD, ECC, UST, GID) |
| `files` | EF directory table (GSM 11.11 / TS 31.102 / 31.103) |
| `profile` | `read_profile()` / `write_profile()` (dry-run by default) |
| `algorithms` | pure-Python AES-128 + Milenage, spec-accurate |
| `ly14` | blank-card private protocols + `replay_template()` |
| `ly14_templates` | 13 card-initialisation sequences extracted verbatim from the vendor binary |

## Reverse-engineered blank-card protocol

Static analysis of GRSIMWrite.exe (every card command is an ASCII-hex string
in the Delphi CODE section) plus headless IDA decompilation of the write-card
functions yielded four protocol generations:

| generation | Ki / OPc write | unlock |
|---|---|---|
| 7FF0 (LY14) | SELECT `3F00/7FF0`, EF `0006`; `A0D6` offset 1 (Ki, 16B), offset 0x11 (OPc, 16B); also mirrored in EFs `000F`/`0012` | VERIFY ADM keyref `0x0B` |
| gen4 `A0FB` | `A0FB <slot> <Lc> <magic><key>` — slots 00 PIN1/PUK1, 10 OPc, 21 PIN2, 29 PUK2, 3F ADM | `A0FB FF FF 08 <SADM>`, keyref `0x0A` |
| gen3 `00D5` | `00D5 1C00 10 <Ki>`, `00D5 0157 10 <OPc>`, `00D4 1B00/01 01 <alg>` | `00E3 0000 08 <SADM>` |
| record `A0D4` | `A0D4 3A01/3A02/3B00/3B02/3A05 08 <PIN1/PIN2/PUK1/PUK2/ADM>` | keyref `0x0B`/`04` |

Bonus: `A0 92 00 00 10` reads the Ki back on some cards, `A0 96 00 01/02`
read the algorithm state, `A0 52` sets the initial PIN, `A053` commits a
rebuilt file system. `replay_template()` re-runs the vendor's full
initialisation (CREATE FILE storm + commit) — dry-run by default, **wipes
the card** when applied.

Open items (need a live blank card): the exact algorithm-selector byte per
algorithm (candidates `0A`/`FF`) and the ATR→template mapping.

## Tests

```powershell
python -m unittest discover -s tests -t .
```

Vector sources: FIPS-197 (AES), 3GPP TS 35.208 (Milenage f2345),
libosmocore `milenage_test.c` (f1\*/f5\*), ETSI TS 135 206 (algorithm spec).

## Legal / responsible use

For provisioning **your own** blank cards and for research/interoperability.
Writing Ki/OPc is only meaningful on cards you own. Wrong ADM keys consume
limited retry counters and can lock a card permanently — the library never
guesses keys.

## Spec references

ETSI TS 102 221 (UICC/FCP), 3GPP TS 31.102 (USIM EFs), TS 31.103 (ISIM),
GSM 11.11 / TS 51.011 (classic SIM), TS 35.206 (Milenage), TS 31.102
Table 4.2.5.1 (AcT bitmask).
