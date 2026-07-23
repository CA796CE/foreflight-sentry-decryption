#!/usr/bin/env python3
"""Test DERIVED traffic-key hypotheses: build candidate AES-128 keys from device
identifiers (serials, MAC/BSSID, SSID, misc strings) via common transforms and
test each vs the len=20 traffic (entropy + optional known-ICAO oracle).

Identifiers come from local_targets.py (git-ignored; see local_targets.example.py).

  derived_keyhunt.py <secure_capture.hex> [--public <public.hex>]
"""
import argparse
import hashlib

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("secure_capture")
ap.add_argument("--public", help="public-mode capture for the ICAO oracle")
a = ap.parse_args()

T = common.load_config()
OWN = common.KEY_OWNSHIP
KNOWN = common.build_oracle(a.public)["icaos"]

L20 = common.load_len20(a.secure_capture)
sample = L20[:150]


def to16(b):
    return (b * (16 // max(len(b), 1) + 1))[:16]


raws = [("mac", bytes.fromhex(T.MAC)), ("mac_rev", bytes.fromhex(T.MAC)[::-1]),
        ("ssid", T.SSID.encode())]
for s in T.SERIALS:
    raws += [(f"serial_ascii:{s}", s.encode()),
             (f"serial_int:{s}", int(s).to_bytes(8, "big")),
             (f"serial_int_le:{s}", int(s).to_bytes(8, "little"))]
for m in getattr(T, "MISC", []):
    raws.append((f"misc:{m}", m.encode()))

cands = {}
for label, b in raws:
    cands[f"pad16:{label}"] = to16(b)
    cands[f"md5:{label}"] = hashlib.md5(b).digest()
    cands[f"sha1:{label}"] = hashlib.sha1(b).digest()[:16]
    cands[f"sha256:{label}"] = hashlib.sha256(b).digest()[:16]
    cands[f"md5(own+b):{label}"] = hashlib.md5(OWN + b).digest()
    cands[f"md5(b+own):{label}"] = hashlib.md5(b + OWN).digest()
    cands[f"sha256(own+b):{label}"] = hashlib.sha256(OWN + b).digest()[:16]
    cands[f"own_xor:{label}"] = bytes(x ^ y for x, y in zip(OWN, to16(b)))
if len(T.SERIALS) >= 2:
    both = (T.SERIALS[0] + T.SERIALS[1]).encode()
    for name, fn in [("md5", lambda x: hashlib.md5(x).digest()),
                     ("sha256", lambda x: hashlib.sha256(x).digest()[:16])]:
        cands[f"{name}:both_serials"] = fn(both)
        cands[f"{name}:both_serials+mac"] = fn(both + bytes.fromhex(T.MAC))
cands["ownship_key_asis"] = OWN   # sanity: must NOT decode traffic

print(f"testing {len(cands)} derived candidates vs {len(sample)} blocks, aligns 2 & 4")
results = []
for label, key in cands.items():
    aes = AES.new(key, AES.MODE_ECB)
    for off in (2, 4):
        dec = aes.decrypt(b"".join(c[off:off + 16] for c in sample))
        e = common.entropy(dec)
        hit = any(ic in dec for ic in KNOWN)
        results.append((e, off, label, key.hex(), hit))
results.sort()
print("\n== best (lowest entropy) derived candidates ==")
for e, off, label, kh, hit in results[:15]:
    print(f"  entropy={e:.3f} align={off} {'ICAO!' if hit else '     '} {label}  key={kh}")
real = [r for r in results if r[4] or r[0] < 6.8]
print("\n== real candidates (crib hit or low entropy) ==")
print("\n".join(f"  {e:.3f} {'ICAO ' if h else ''}{l} key={k}"
                for e, o, l, k, h in real) if real else "  NONE (all ~random entropy)")
