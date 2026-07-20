#!/usr/bin/env python3
"""Capture the Sentry's UDP :4000 GDL90 stream and print decoded frames.
Usage: show_gdl90.py [seconds]   (default 10)"""
import socket, time, sys

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 10
_crc = []
for i in range(256):
    c = (i << 8) & 0xFFFF
    for _ in range(8):
        c = ((c << 1) ^ (0x1021 if c & 0x8000 else 0)) & 0xFFFF
    _crc.append(c)
def crc(data):
    c = 0
    for b in data:
        c = (_crc[c >> 8] ^ ((c << 8) & 0xFFFF) ^ b) & 0xFFFF
    return c
def destuff(p):
    o = bytearray(); i = 0
    while i < len(p):
        b = p[i]
        if b == 0x7d:
            i += 1
            if i < len(p): o.append(p[i] ^ 0x20)
        else: o.append(b)
        i += 1
    return bytes(o)
def s24(b):
    v = (b[0] << 16) | (b[1] << 8) | b[2]
    return v - 0x1000000 if v & 0x800000 else v
NAMES = {0x00: "Heartbeat", 0x0A: "Ownship", 0x14: "Traffic",
         0x0B: "OwnshipGeoAlt", 0x07: "Uplink", 0x21: "uAvionix-0x21",
         0x25: "uAvionix-status", 0x28: "uAvionix-0x28"}
def show(c):
    mid = c[0]; name = NAMES.get(mid, f"msg-0x{mid:02x}")
    if mid in (0x0A, 0x14) and len(c) >= 27:
        lat = s24(c[5:8]) * (180.0 / 2**23); lon = s24(c[8:11]) * (180.0 / 2**23)
        a = (c[11] << 4) | (c[12] >> 4); alt = a * 25 - 1000 if a != 0xFFF else None
        cs = bytes(c[19:27]).decode('latin1').strip()
        addr = (c[2] << 16) | (c[3] << 8) | c[4]
        return f"{name:14} addr={addr:06X} call={cs or '-':8} lat={lat:.5f} lon={lon:.5f} alt={alt}ft"
    return f"{name:14} ({len(c)} B) {c.hex()}"

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 4000)); s.settimeout(0.5)
print(f"listening on :4000 for {DUR}s ...", file=sys.stderr)
KNOWN = set(NAMES)   # ids we already recognize
seen = {}; samples = {}; lengths = {}; t = time.time()
traffic_addrs = set(); max_rx = 0; next_prog = t + 60
while time.time() - t < DUR:
    try: d, _ = s.recvfrom(4096)
    except socket.timeout:
        pass
    else:
        for part in d.split(b'\x7e'):
            if not part: continue
            de = destuff(part)
            if len(de) < 3: continue
            body, rx = de[:-2], de[-2] | (de[-1] << 8)
            if crc(body) != rx: continue
            mid = body[0]
            seen[mid] = seen.get(mid, 0) + 1
            samples.setdefault(mid, body.hex()); lengths.setdefault(mid, set()).add(len(body))
            if mid == 0x00 and len(body) >= 7:
                max_rx = max(max_rx, ((body[5] & 0x03) << 8) | body[6])
            if mid == 0x14 and len(body) >= 27:
                addr = (body[2] << 16) | (body[3] << 8) | body[4]
                if addr not in traffic_addrs:
                    traffic_addrs.add(addr); print("TRAFFIC> " + show(body), flush=True)
            if mid not in KNOWN and seen[mid] == 1:
                print(f"UNRECOGNIZED> id=0x{mid:02x} ({len(body)}B) {body.hex()}", flush=True)
    now = time.time()
    if now >= next_prog:
        el = int(now - t)
        print(f"[t={el:3d}s] rx_msgs={max_rx} traffic={len(traffic_addrs)} "
              f"ids={sorted(hex(k) for k in seen)}", file=sys.stderr, flush=True)
        next_prog = now + 60
print("\n=== FRAME CATALOG (id: count, len, sample) ===", file=sys.stderr)
for k in sorted(seen):
    tag = NAMES.get(k, f"UNKNOWN-0x{k:02x}")
    print(f"  0x{k:02x} {tag:16} x{seen[k]:<5} len={sorted(lengths[k])}  {samples[k][:48]}", file=sys.stderr)
print(f"\n  ADS-B msgs received (heartbeat max): {max_rx}", file=sys.stderr)
print(f"  distinct TRAFFIC targets: {len(traffic_addrs)}  {[hex(a) for a in traffic_addrs]}", file=sys.stderr)
