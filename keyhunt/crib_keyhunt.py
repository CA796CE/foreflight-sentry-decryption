#!/usr/bin/env python3
"""Wider known-plaintext attack. Decode the public-mode 0x21 traffic to get each
aircraft's ICAO and callsign, then brute-force every firmware window as an
AES-128-ECB key, checking each decrypt for ANY exact crib. Exact cribs catch the
right key even when the plaintext is too dense for entropy to flag it.

  crib_keyhunt.py <firmware.bin> <public_capture.hex> <secure_capture.hex>
"""
import argparse
import sys

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("firmware")
ap.add_argument("public_capture")
ap.add_argument("secure_capture")
a = ap.parse_args()

oracle = common.build_oracle(a.public_capture)
print("ICAOs:", oracle["raw_icaos"])
print("callsigns:", oracle["callsigns"])
long_cribs, icao3 = oracle["long_cribs"], oracle["icao3"]
print(f"{len(long_cribs)} long cribs (>=4B), {len(icao3)} 3-byte ICAO cribs")

L20 = common.load_len20(a.secure_capture)
blob = b"".join(c[2:18] for c in L20)      # block at offset 2 (pinned by repeats)
print(f"secure len=20 blocks: {len(L20)} ({len(blob)} bytes)\n", flush=True)

fw = open(a.firmware, "rb").read()
hits, icao_hits = [], []
for koff in range(len(fw) - 15):
    dec = AES.new(fw[koff:koff + 16], AES.MODE_ECB).decrypt(blob)
    for label, cb in long_cribs:
        if cb in dec:
            hits.append((koff, label, cb.hex()))
            break
    for label, cb in icao3:
        if cb in dec:
            icao_hits.append((koff, label))
            break
    if koff and koff % 200000 == 0:
        print(f"  ...{koff}", file=sys.stderr, flush=True)

print("== LONG-CRIB hits (callsign / ME / >=4B) ==")
print("\n".join(f"  fw@0x{k:05x} {l} crib={c}" for k, l, c in hits[:40]) or "  none")
expect = (len(fw) * len(blob) * len(icao3)) / 2 ** 24 if icao3 else 0
print(f"\n== 3-byte ICAO hits: {len(icao_hits)} (expect ~{expect:.1f} by chance) ==")
for k, l in icao_hits[:20]:
    print(f"  fw@0x{k:05x} {l}")
if not hits:
    print("\nNo exact callsign/ME/ICAO crib decrypts under any firmware key -> the "
          "traffic key is not a constant in this image, even with wider cribs.")
