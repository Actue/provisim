"""Command-line interface: python -m provisim.cli <command> ...

Commands:
  readers                     list PC/SC readers
  info [--reader NAME]        ATR, applications, ICCID/IMSI if readable
  read  [-o FILE] [--json]    dump the full profile (read_profile)
  dump-ef KEY [--app APP]     raw hex of one EF
  write -i FILE [--adm KEY] [--yes] [--only F,F..]
                             apply a profile (dry-run unless --yes)
  apdu HEX                    send a raw APDU (development / RE aid)
  pin verify|change|unblock   PIN/ADM operations
"""

from __future__ import annotations

import argparse
import json
import sys

from . import codec
from .apdu import CardError, PinRetryError
from .card import UiccCard
from .files import App
from .profile import SimProfile, read_profile, write_profile
from .transport import PcscTransport, ReaderNotFoundError, list_readers


def _open_card(reader: str = None) -> UiccCard:
    t = PcscTransport(reader)
    t.connect()
    return UiccCard(t)


def _card_or_die(reader: str = None) -> UiccCard:
    try:
        return _open_card(reader)
    except ReaderNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)


def cmd_readers(args):
    rs = list_readers()
    if not rs:
        print("no readers found")
        return 1
    for i, r in enumerate(rs):
        print(f"{i}: {r}")
    return 0


def cmd_info(args):
    card = _card_or_die(args.reader)
    print(f"ATR   : {codec.b2h(card.atr)}")
    apps = card.detect_apps()
    print(f"Apps  : " + " ".join(k for k, v in apps.items() if v))
    try:
        ef = card.read_ef("ICCID")
        iccid = codec.decode_iccid(ef.data)
        luhn = "ok" if codec.iccid_luhn_ok(iccid) else "BAD"
        print(f"ICCID : {iccid} (Luhn {luhn})")
    except CardError as e:
        print(f"ICCID : <unreadable: {e}>")
    for app_key in ("USIM", "GSM"):
        if apps.get(app_key):
            try:
                ef = card.read_ef("IMSI", app=None)
                print(f"IMSI  : {codec.decode_imsi(ef.data)}")
                break
            except CardError:
                pass
    return 0


def cmd_read(args):
    card = _card_or_die(args.reader)
    p = read_profile(card)
    if args.out:
        open(args.out, "w", encoding="utf-8").write(p.to_json())
        print(f"written to {args.out}", file=sys.stderr)
    print(p.to_json())
    return 0


def cmd_dump_ef(args):
    card = _card_or_die(args.reader)
    app = getattr(App, args.app) if args.app else None
    ef = card.read_ef(args.key, app)
    print(ef.hex())
    return 0


def cmd_write(args):
    profile = SimProfile.from_json(open(args.file, encoding="utf-8").read())
    card = _card_or_die(args.reader)
    only = args.only.split(",") if args.only else None
    log = write_profile(card, profile, adm=args.adm,
                        dry_run=not args.yes, only=only)
    for line in log:
        print(line)
    if not args.yes:
        print("\n(dry run — add --yes to write, --adm HEX_KEY required)")
    return 0


def cmd_apdu(args):
    card = _card_or_die(args.reader)
    try:
        resp, _ = card.transmit_raw(args.hexstr)
        print(codec.b2h(resp) + " 9000")
        return 0
    except (CardError, PinRetryError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


def cmd_pin(args):
    card = _card_or_die(args.reader)
    ref = int(args.ref, 0)
    try:
        if args.action == "verify":
            card.verify_pin(ref, args.value, context=args.action)
            print("OK")
        elif args.action == "change":
            card.change_pin(ref, args.old, args.new)
            print("changed")
        elif args.action == "unblock":
            card.unblock_pin(ref, args.old, args.new)
            print("unblocked")
        return 0
    except PinRetryError as e:
        print(f"failed: {e} ({e.retries_left} retries left)", file=sys.stderr)
        return 1
    except CardError as e:
        print(f"failed: {e}", file=sys.stderr)
        return 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="provisim", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("readers").set_defaults(fn=cmd_readers)

    for name in ("info", "read", "dump-ef", "write", "apdu", "pin"):
        p = sub.add_parser(name)
        p.add_argument("--reader", "-r", default=None)
        if name == "read":
            p.add_argument("-o", "--out", default=None)
            p.add_argument("--json", action="store_true")
        if name == "dump-ef":
            p.add_argument("key")
            p.add_argument("--app", default=None)
        if name == "write":
            p.add_argument("-i", "--file", required=True)
            p.add_argument("--adm", default=None)
            p.add_argument("--yes", action="store_true")
            p.add_argument("--only", default=None)
        if name == "apdu":
            p.add_argument("hexstr")
        if name == "pin":
            p.add_argument("action", choices=["verify", "change", "unblock"])
            p.add_argument("--ref", default="0x08")
            p.add_argument("--value", default=None)
            p.add_argument("--old", default=None)
            p.add_argument("--new", default=None)
        p.set_defaults(fn=globals()[f"cmd_{name.replace('-', '_')}"])

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
