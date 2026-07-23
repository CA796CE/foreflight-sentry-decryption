#!/usr/bin/env python3
"""Cryptanalysis diagnostic: could the traffic be the *ownship* key in a non-ECB
mode (e.g. serial as IV), or a fixed-keystream stream cipher? A fixed IV cancels
in pairwise XOR and a fixed keystream cancels in raw-ciphertext pairwise XOR, so
either would leave shared-plaintext structure visible. This measures it.

Interpretation:
  * per-byte-position entropy ~max at every position AND D_i^D_j pure random
      -> ownship key is wrong under ANY fixed IV (CBC/CFB/OFB) too.
  * raw ct_i^ct_j pure random -> not a fixed-keystream stream cipher (CTR/OFB).
  * only exact 16-byte block repeats survive -> plain ECB, independent key.

  mode_test.py <secure_capture.hex>
"""
import argparse
import collections
import itertools

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("secure_capture")
a = ap.parse_args()

dec = AES.new(common.KEY_OWNSHIP, AES.MODE_ECB)
L20 = common.load_len20(a.secure_capture)
CT = [bytes(c[2:18]) for c in L20]                 # raw ciphertext blocks (offset 2)
D = [dec.decrypt(c) for c in CT]                   # ownship-key ECB-decrypt
print(f"{len(CT)} distinct len=20 traffic blocks\n")


def col_entropy(blocks):
    return [common.entropy([b[i] for b in blocks]) for i in range(16)]


print("per-byte-position entropy, ownship-key-decrypted (low = structure => right key):")
print("  " + " ".join(f"{e:.2f}" for e in col_entropy(D)))
print("per-byte-position entropy, RAW ciphertext:")
print("  " + " ".join(f"{e:.2f}" for e in col_entropy(CT)))


def pair_equal_dist(blocks, n=40000):
    zc = collections.Counter()
    for x, y in itertools.islice(itertools.combinations(range(len(blocks)), 2), n):
        zc[sum(1 for p, q in zip(blocks[x], blocks[y]) if p == q)] += 1
    return zc


print("\nD_i vs D_j equal-byte-count (IV cancels; peak>0 => shared plaintext):")
for k in sorted(pair_equal_dist(D))[:6]:
    print(f"  {k}: {pair_equal_dist(D)[k]}")
print("\nraw ct_i vs ct_j equal-byte-count (keystream cancels; peak>0 => stream cipher):")
zc = pair_equal_dist(CT)
for k in sorted(zc)[:6]:
    print(f"  {k}: {zc[k]}")
print("\n(random baseline: ~%.0f pairs with exactly 1 equal byte per 40000)" % (40000 * 16 / 256))
