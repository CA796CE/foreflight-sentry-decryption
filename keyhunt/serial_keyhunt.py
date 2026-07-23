#!/usr/bin/env python3
"""Thorough per-device key derivation focused on the SERIAL NUMBER. Includes the
embedded KDF traffic_key = AES(master, serial), BCD/int encodings, HMAC(master,
id), many salts, and combinations. Tests each vs the len=20 traffic (entropy +
optional ICAO/callsign oracle).

Identifiers from local_targets.py (git-ignored; see local_targets.example.py).

  serial_keyhunt.py <secure_capture.hex> [--public <public.hex>]
"""
import argparse
import hashlib
import hmac

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("secure_capture")
ap.add_argument("--public", help="public-mode capture for the ICAO/callsign oracle")
a = ap.parse_args()

T = common.load_config()
OWN = common.KEY_OWNSHIP
oracle = common.build_oracle(a.public)
KNOWN = oracle["icaos"]
CALLS = [b for _, b in oracle["long_cribs"]]

L20 = common.load_len20(a.secure_capture)
blob = b"".join(c[2:18] for c in L20[:200])


def pad16(b):
    return (b * (16 // max(len(b), 1) + 1))[:16]


def zp16(b):
    return (b + b"\0" * 16)[:16]


def aes_enc(key, pt):
    return AES.new(pad16(key), AES.MODE_ECB).encrypt(zp16(pt))


salts = [OWN, b"ForeFlight", b"uAvionix", b"pingESP32", b"SentryPlus", b"sentry",
         b"GDL90", b"traffic", b""]


def forms(s):
    out = {f"ascii:{s}": s.encode(), f"ascii_pad:{s}": pad16(s.encode()), f"rev:{s}": s[::-1].encode()}
    try:
        out[f"bcd:{s}"] = bytes.fromhex(s if len(s) % 2 == 0 else "0" + s)
    except ValueError:
        pass
    try:
        n = int(s)
        out[f"int_be:{s}"] = n.to_bytes(8, "big")
        out[f"int_le:{s}"] = n.to_bytes(8, "little")
    except ValueError:
        pass
    return out


idforms = {}
strs = list(T.SERIALS) + [T.SSID]
if len(T.SERIALS) >= 2:
    strs += [f"{T.SERIALS[0]} : {T.SERIALS[1]}", T.SERIALS[0] + T.SERIALS[1], T.SERIALS[1] + T.SERIALS[0]]
for s in strs:
    idforms.update(forms(s))
mac = bytes.fromhex(T.MAC)
idforms["mac"] = mac
idforms["mac_rev"] = mac[::-1]

cands = {}
for label, b in idforms.items():
    cands[f"pad:{label}"] = pad16(b)
    cands[f"zp:{label}"] = zp16(b)
    cands[f"md5:{label}"] = hashlib.md5(b).digest()
    cands[f"sha1:{label}"] = hashlib.sha1(b).digest()[:16]
    cands[f"sha256:{label}"] = hashlib.sha256(b).digest()[:16]
    cands[f"AESenc(own,id):{label}"] = aes_enc(OWN, b)   # KDF: encrypt id with master
    cands[f"AESenc(id,own):{label}"] = aes_enc(b, OWN)
    cands[f"hmac256(own,id):{label}"] = hmac.new(OWN, b, hashlib.sha256).digest()[:16]
    cands[f"hmac_md5(own,id):{label}"] = hmac.new(OWN, b, hashlib.md5).digest()
    cands[f"hmac256(id,own):{label}"] = hmac.new(pad16(b), OWN, hashlib.sha256).digest()[:16]
    for sa in salts:
        cands[f"md5({sa[:6]!r}+id):{label}"] = hashlib.md5(sa + b).digest()
        cands[f"md5(id+{sa[:6]!r}):{label}"] = hashlib.md5(b + sa).digest()
        cands[f"sha256({sa[:6]!r}+id):{label}"] = hashlib.sha256(sa + b).digest()[:16]
    cands[f"own_xor:{label}"] = bytes(x ^ y for x, y in zip(OWN, pad16(b)))

print(f"testing {len(cands)} serial/derived candidates vs {len(L20)} traffic blocks")
res = []
for label, key in cands.items():
    dec = AES.new(key, AES.MODE_ECB).decrypt(blob)
    e = common.entropy(dec)
    icao = any(ic in dec for ic in KNOWN)
    call = any(c in dec for c in CALLS)
    res.append((e, label, key.hex(), icao, call))
res.sort()
print("\n== best (lowest entropy) ==")
for e, label, kh, icao, call in res[:18]:
    flag = "ICAO!" if icao else ("CALL!" if call else "")
    print(f"  {e:.3f} {flag:5s} {label}  key={kh}")
real = [r for r in res if r[3] or r[4] or r[0] < 6.8]
print("\n== real candidates (crib hit or low entropy) ==")
print("\n".join(f"  {e:.3f} {'ICAO' if i else ''}{'CALL' if c else ''} {l} key={k}"
                for e, l, k, i, c in real) if real else "  NONE")
