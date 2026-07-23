#!/usr/bin/env python3
"""Meta-brute-force for a per-device serial-derived key:
   K_traffic = AES_ECB(K_master).encrypt(serial_form)
where K_master is ANY 16-byte firmware window (a baked master key, possibly
different from the ownship key). Tests each derived key vs the len=20 traffic
(entropy + optional known-ICAO oracle).

Serials/MAC from local_targets.py (git-ignored; see local_targets.example.py).

  serial_kdf_bruteforce.py <firmware.bin> <secure_capture.hex> [--public <public.hex>]
"""
import argparse

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("firmware")
ap.add_argument("secure_capture")
ap.add_argument("--public", help="public-mode capture for the ICAO oracle")
a = ap.parse_args()

T = common.load_config()
KNOWN = common.build_oracle(a.public)["icaos"]


def zp16(b):
    return (b + b"\0" * 16)[:16]


def pad16(b):
    return (b * (16 // max(len(b), 1) + 1))[:16]


# serial/id plaintexts to encrypt under each candidate master
idforms = {"mac_zp": zp16(bytes.fromhex(T.MAC))}
for i, s in enumerate(T.SERIALS):
    try:
        idforms[f"s{i}_bcd_zp"] = zp16(bytes.fromhex(s if len(s) % 2 == 0 else "0" + s))
    except ValueError:
        pass
    idforms[f"s{i}_ascii"] = pad16(s.encode())
if len(T.SERIALS) >= 2:
    try:
        idforms["s01_bcd"] = zp16(bytes.fromhex(T.SERIALS[0]) + bytes.fromhex(T.SERIALS[1]))
    except ValueError:
        pass

L20 = common.load_len20(a.secure_capture)
blob = b"".join(c[2:18] for c in L20[:60])   # small sample: 2 AES per candidate

fw = open(a.firmware, "rb").read()
print(f"{len(fw) - 15} masters x {len(idforms)} id-forms", flush=True)
best, hits = [], []
for koff in range(len(fw) - 15):
    menc = AES.new(fw[koff:koff + 16], AES.MODE_ECB)
    for name, pt in idforms.items():
        key = menc.encrypt(pt)
        dec = AES.new(key, AES.MODE_ECB).decrypt(blob)
        e = common.entropy(dec)
        if e < 7.0:
            best.append((e, koff, name, key.hex()))
        if e < 7.3 and KNOWN and any(ic in dec for ic in KNOWN):
            hits.append((koff, name, key.hex(), round(e, 3)))
    if koff and koff % 150000 == 0:
        print(f"  ...{koff} best={min((b[0] for b in best), default=9):.3f}", flush=True)

best.sort()
print("\n== lowest-entropy derived keys ==")
for e, koff, name, kh in best[:15]:
    print(f"  {e:.3f} master@0x{koff:05x} id={name} K={kh}")
if not best:
    print("  (nothing below 7.0)")
print("\n== ICAO-confirmed hits ==", hits[:15] or "none")
if not best and not hits:
    print("\nVERDICT: no firmware-master + serial KDF produces the traffic key.")
