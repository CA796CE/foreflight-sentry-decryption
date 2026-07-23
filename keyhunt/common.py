"""Shared helpers for the traffic-key search scripts.

The AES *ownship* key below is the already-published finding (see the repo README
and firmware-crypto-notes.md), so hardcoding it here leaks nothing new. Everything
device-specific (serials, MAC, SSID) is read from `local_targets.py`, which is
git-ignored — copy `local_targets.example.py` and fill it in. The ICAO/callsign
oracle is decoded from a public-mode capture you pass on the command line, so it
never has to be committed either.
"""
import collections
import math

# Published finding — AES-128-ECB, null IV. Decrypts ownship (0x27/0x28) only.
KEY_OWNSHIP = bytes.fromhex("a6b1c01f2200566268937c708a06ddcf")

# Mode S 6-bit identity charset (DF17 TC1-4 callsigns).
CHARMAP = "#ABCDEFGHIJKLMNOPQRSTUVWXYZ##### ###############0123456789######"


def destuff(p):
    """Reverse GDL90 byte-stuffing (0x7d 0x5e/0x5d -> 0x7e/0x7d)."""
    o = bytearray()
    i = 0
    while i < len(p):
        b = p[i]
        if b == 0x7D:
            i += 1
            if i < len(p):
                o.append(p[i] ^ 0x20)
        else:
            o.append(b)
        i += 1
    return bytes(o)


def entropy(bs):
    if not bs:
        return 0.0
    c = collections.Counter(bs)
    n = len(bs)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def iter_frames(path):
    """Yield each GDL90 frame's content (destuffed, CRC-stripped) from a capture
    file whose lines are '<epoch> <hex>' or just '<hex>' (0x7e-delimited)."""
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        d = bytes.fromhex(line.split()[-1])
        for part in d.split(b"\x7e"):
            if not part:
                continue
            de = destuff(part)
            if len(de) < 3:
                continue
            yield de[:-2]


def load_len20(path):
    """Distinct 0x26 len==20 (traffic) frame contents, in first-seen order."""
    seen = set()
    out = []
    for body in iter_frames(path):
        if body[0] == 0x26 and len(body) == 20:
            h = bytes(body)
            if h not in seen:
                seen.add(h)
                out.append(h)
    return out


def callsign_from_me(me):
    """Decode the 8-char callsign from a DF17 TC1-4 ME field (7 bytes)."""
    bits = 0
    for b in me[1:7]:
        bits = (bits << 8) | b
    cs = "".join(CHARMAP[(bits >> (6 * (7 - i))) & 0x3F] for i in range(8))
    return cs.replace("#", "").strip()


def decode_public(path):
    """From a public-mode capture (traffic as 0x21 raw DF17), return
    (icaos:set[bytes], callsigns:dict[bytes->str], me_ident:dict[bytes->bytes])."""
    icaos, calls, me_ident = set(), {}, {}
    for body in iter_frames(path):
        if body[0] == 0x21 and len(body) >= 11:
            m = body[4:]
            if (m[0] >> 3) in (17, 18):
                ic = bytes(m[1:4])
                icaos.add(ic)
                if 1 <= (m[4] >> 3) <= 4 and len(m) >= 11:
                    cs = callsign_from_me(m[4:11])
                    if cs:
                        calls[ic] = cs
                        me_ident[ic] = bytes(m[4:11])
    return icaos, calls, me_ident


def build_oracle(public_path):
    """Decode a known-plaintext oracle from a public-mode capture. Returns a dict:
      icaos      : list of ICAO bytes (both byte orders) for membership tests
      long_cribs : list of (label, bytes>=4) — callsign ASCII/padded + 6-bit ME
      icao3      : list of (label, 3-byte ICAO) — short, high false-positive
      raw_icaos, callsigns : for display
    Empty oracle if public_path is falsy (entropy-only mode)."""
    if not public_path:
        return {"icaos": [], "long_cribs": [], "icao3": [], "raw_icaos": [], "callsigns": {}}
    icaos, calls, me_ident = decode_public(public_path)
    known = list(icaos) + [ic[::-1] for ic in icaos]
    long_cribs, icao3 = [], []
    for ic in icaos:
        icao3.append(("icao_be:" + ic.hex(), ic))
        icao3.append(("icao_le:" + ic.hex(), ic[::-1]))
    for ic, cs in calls.items():
        long_cribs.append((f"call_ascii:{cs}", cs.encode()))
        long_cribs.append((f"call_pad:{cs}", cs.ljust(8).encode()))
    for ic, me in me_ident.items():
        long_cribs.append((f"me_ident:{calls.get(ic, '')}", me[1:7]))
    return {"icaos": known, "long_cribs": long_cribs, "icao3": icao3,
            "raw_icaos": sorted(ic.hex() for ic in icaos),
            "callsigns": {ic.hex(): cs for ic, cs in calls.items()}}


def load_config():
    """Import local_targets.py (git-ignored device identifiers). Helpful error if
    missing."""
    try:
        import local_targets
    except ImportError:
        raise SystemExit(
            "This search needs device identifiers. Copy local_targets.example.py "
            "-> local_targets.py (git-ignored) and fill in SERIALS / MAC / SSID.")
    return local_targets
