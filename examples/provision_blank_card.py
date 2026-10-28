"""Provision a blank programmable card from a vendor-GUI-style parameter
sheet (the "LTE/WCDMA Parameter" form of GRSIMWrite-like tools).

Parameter sheet this translates:

    IMSI        460065034693035          -> EF_IMSI
    Ki          00112233...DDEEFF        -> private DF (generation-dependent)
    key type    OP                       -> OPc = compute_opc(K, OP) on host
    OP          63BFA50E...88737D        (TS 35.206 Annex 3 reference OP)
    Algorithm   Milenage
    AD          00000002                 -> EF_AD raw bytes
    HPLMNwAct   46006:8000               -> EF_HPLMNwAcT record (460-06, UTRAN)
    EHPLMN      46006                    -> EF_EHPLMN
    PLMNwAct    46006:8000               -> EF_PLMNwAcT record

Usage:
    python examples/provision_blank_card.py            # preview only (no card I/O)
    python examples/provision_blank_card.py --apply    # REALLY writes (blank card only!)
    python examples/provision_blank_card.py --template 5 --apply
"""

import sys

sys.path.insert(0, ".")

from provisim import codec
from provisim.algorithms import compute_opc
from provisim.card import UiccCard
from provisim.files import App
from provisim.ly14 import Ly14Card

# ------------------------------------------------------------------ parameters
IMSI = "460000000000000"   # <-- REPLACE with your IMSI (15 or 18 digits)
KI = "00112233445566778899AABBCCDDEEFF"
OP = "63BFA50EE6523365FF14C1F45F88737D"   # TS 35.206 reference OP
AD_RAW = "00000002"                        # as shown by the vendor form
HPLMNWACT = [("460-06", 0x8000)]           # 46006:8000 -> 460-06 + UTRAN
EHPLMN = ["460-06"]
PLMNWACT = [("460-06", 0x8000)]
ALGORITHM = "Milenage"

ADM = "3838383838383838"                   # factory default '88888888'

# ------------------------------------------------------------------ derived
OPC = compute_opc(codec.h2b(KI), codec.h2b(OP))

def plmn_act_blob(entries, fill_to=40):
    blob = b"".join(codec.encode_plmn_w_act(p, a) for p, a in entries)
    return blob.ljust(fill_to, b"\xff")[:fill_to]

def apply(card: UiccCard):
    """All card-touching steps, in vendor-GUI order."""
    print("[*] probing protocol generation (read-only)...")
    print("    ", card.probe())

    print("[*] verifying ADM ...")
    card.verify_adm(ADM)

    # -- standard USIM EFs ------------------------------------------------
    card.select_app(App.ADF_USIM)
    print("[*] IMSI    ->", codec.encode_imsi(IMSI).hex().upper())
    card.update_ef_data("IMSI", codec.encode_imsi(IMSI))
    print("[*] AD      ->", AD_RAW)
    card.update_ef_data("AD", codec.h2b(AD_RAW))
    print("[*] HPLMNwAcT ->", plmn_act_blob(HPLMNWACT).hex().upper()[:20], "...")
    card.update_ef_data("HPLMNWACT", plmn_act_blob(HPLMNWACT))
    print("[*] EHPLMN  ->", codec.encode_plmn_list(EHPLMN, 5).hex().upper())
    card.update_ef_data("EHPLMN", codec.encode_plmn_list(EHPLMN, 5))
    print("[*] PLMNwAcT ->", plmn_act_blob(PLMNWACT).hex().upper()[:20], "...")
    card.update_ef_data("PLMNWACT", plmn_act_blob(PLMNWACT))

    # -- private keys -------------------------------------------------------
    print("[*] Ki  ->", KI)
    card.set_ki(KI)
    print("[*] OPc ->", OPC.hex().upper(), " (computed from OP on host)")
    card.set_opc(OPC.hex().upper())

    # -- verify what we can read back --------------------------------------
    try:
        print("[*] read back Ki:", card.read_ki().hex().upper())
    except Exception as e:  # noqa: BLE001
        print("[*] Ki readback not supported:", e)

def preview():
    print("=== parameter sheet -> card operations (DRY RUN, no I/O) ===\n")
    print(f"IMSI        {IMSI}")
    print(f"  EF_IMSI   {codec.encode_imsi(IMSI).hex().upper()}")
    print(f"Ki          {KI}")
    print(f"OP          {OP}   (TS 35.206 reference)")
    print(f"  OPc       {OPC.hex().upper()}   = compute_opc(Ki, OP)")
    print(f"AD          {AD_RAW}")
    print(f"HPLMNwAcT   {HPLMNWACT}  -> {codec.encode_plmn_w_act('460-06', 0x8000).hex().upper()}")
    print(f"EHPLMN      {EHPLMN}  -> {codec.encode_plmn_list(EHPLMN, 5).hex().upper()}")
    print(f"PLMNwAcT    {PLMNWACT}  -> {codec.encode_plmn_w_act('460-06', 0x8000).hex().upper()}")
    print(f"Algorithm   {ALGORITHM} (selector byte: 0A / FF — pin down with read_state())")
    print(f"ADM         {ADM}\n")
    print("Sequence: probe -> verify_adm -> [IMSI AD HPLMNwAcT EHPLMN PLMNwAcT]")
    print("           -> set_ki -> set_opc(compute_opc) -> read_ki")
    print("Optional full rebuild first: Ly14Card.replay_template(n) (wipes card!)")

def main():
    if "--apply" not in sys.argv:
        preview()
        return
    from provisim import PcscTransport
    with PcscTransport() as t:
        apply(Ly14Card(t))
    print("\ndone.")

if __name__ == "__main__":
    main()
