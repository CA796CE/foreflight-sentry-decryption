#!/usr/bin/env python3
"""Brute-force the TRAFFIC key against firmware: try every 16-byte window of a
firmware image as an AES-128-ECB key vs the 0x26 len=20 traffic ciphertext.

Scored by decrypted entropy (the ownship key dipped to ~6.96 vs ~7.85 random),
plus an optional known-ICAO oracle decoded from a public-mode capture (--public).
We don't know the exact 16-byte block offset inside the 20-byte content
(26 00 + 18B), so try offset 2 (16B ct + 2B trailer) and 4 (2B hdr + 16B ct).

  keyhunt.py <firmware.bin> <secure_capture.hex> [--public <public.hex>]
"""
import argparse
import heapq
import sys
import time

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("firmware")
ap.add_argument("secure_capture")
ap.add_argument("--public", help="public-mode capture for the ICAO oracle (optional)")
ap.add_argument("--aligns", default="2,4")
ap.add_argument("--topk", type=int, default=25)
ap.add_argument("--sample", type=int, default=120)
a = ap.parse_args()

ALIGNS = [int(x) for x in a.aligns.split(",")]
KNOWN = common.build_oracle(a.public)["icaos"]
L20 = common.load_len20(a.secure_capture)
print(f"distinct len=20 traffic frames: {len(L20)}   known ICAOs: {len(KNOWN) // 2}", flush=True)

sample = L20[:a.sample]
blobs = {off: b"".join(c[off:off + 16] for c in sample) for off in ALIGNS}

fw = open(a.firmware, "rb").read()
ncand = len(fw) - 15
print(f"firmware {len(fw)} bytes -> {ncand} candidate keys x {len(ALIGNS)} aligns", flush=True)

heaps = {off: [] for off in ALIGNS}   # TOPK lowest-entropy per alignment (max-heap via -e)
icao_hits = []
t0 = time.time()
for koff in range(ncand):
    aes = AES.new(fw[koff:koff + 16], AES.MODE_ECB)
    for off in ALIGNS:
        dec = aes.decrypt(blobs[off])
        e = common.entropy(dec)
        h = heaps[off]
        if len(h) < a.topk:
            heapq.heappush(h, (-e, koff))
        elif -e > h[0][0]:
            heapq.heapreplace(h, (-e, koff))
        if e < 7.2 and KNOWN:
            for ic in KNOWN:
                if ic in dec:
                    icao_hits.append((koff, off, ic.hex(), round(e, 3)))
                    break
    if koff and koff % 100000 == 0:
        cur = min(min(-x[0] for x in heaps[o]) for o in ALIGNS)
        print(f"  {koff}/{ncand}  {koff / (time.time() - t0):.0f} keys/s  best_entropy={cur:.3f}",
              file=sys.stderr, flush=True)

print(f"\ndone in {time.time() - t0:.0f}s")
for off in ALIGNS:
    print(f"\n== align={off}: lowest-entropy candidates ==")
    for nege, koff in sorted(heaps[off]):
        print(f"  entropy={-nege:.3f} fw@0x{koff:05x} key={fw[koff:koff + 16].hex()}")
print("\n== known-ICAO hits ==")
print("\n".join(f"  fw@0x{k:05x} align={o} ICAO={ic} entropy={e}"
                for k, o, ic, e in icao_hits[:30]) or "  none")

allbest = min(min(-x[0] for x in heaps[o]) for o in ALIGNS)
if allbest > 7.3 and not icao_hits:
    print("\nVERDICT: no firmware window works -> traffic key is not a constant in "
          "this image (likely derived, or in a newer firmware).")
else:
    print("\nVERDICT: promising candidate(s) above -- verify by full decrypt + DF17 parse.")
