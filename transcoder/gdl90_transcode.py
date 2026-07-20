#!/usr/bin/env python3
"""Sentry (compatibility/public mode) -> standard GDL90 transcoder.

Reads the Sentry's UDP :4000 stream, passes standard messages through
(0x00 Heartbeat, 0x0A Ownship, 0x0B OwnshipGeoAlt), and converts the
proprietary 0x21 raw-ADS-B (Mode S DF17) traffic into standard GDL90
0x14 Traffic Reports so any EFB can use it.

Usage: gdl90_transcode.py <seconds> [out_hexfile] [dst_ip:port]
Requires pyModeS<3 (v2 per-field API).
"""
import socket, sys, time
import pyModeS as pms

DUR = int(sys.argv[1]) if len(sys.argv) > 1 else 20
OUTFILE = sys.argv[2] if len(sys.argv) > 2 else None
DST = None
if len(sys.argv) > 3:
    ip, port = sys.argv[3].split(':'); DST = (ip, int(port))

# ---- GDL90 CRC + framing ----
_crc = []
for i in range(256):
    c = (i << 8) & 0xFFFF
    for _ in range(8):
        c = ((c << 1) ^ (0x1021 if c & 0x8000 else 0)) & 0xFFFF
    _crc.append(c)
def gdl_crc(d):
    c = 0
    for b in d:
        c = (_crc[c >> 8] ^ ((c << 8) & 0xFFFF) ^ b) & 0xFFFF
    return c
def frame(body):
    c = gdl_crc(body)
    raw = bytes(body) + bytes([c & 0xFF, (c >> 8) & 0xFF])
    out = bytearray([0x7E])
    for b in raw:
        if b == 0x7E: out += b'\x7d\x5e'
        elif b == 0x7D: out += b'\x7d\x5d'
        else: out.append(b)
    out.append(0x7E)
    return bytes(out)
def destuff(p):
    o = bytearray(); i = 0
    while i < len(p):
        b = p[i]
        if b == 0x7D:
            i += 1
            if i < len(p): o.append(p[i] ^ 0x20)
        else: o.append(b)
        i += 1
    return bytes(o)

def enc_ll(v):
    x = int(round(v * (0x800000 / 180.0))) & 0xFFFFFF
    return [(x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF]

def make_0x14(icao, lat, lon, alt, gs, trk, vs, call, cat=1):
    b = bytearray(28)
    b[0] = 0x14
    b[1] = 0x00                                  # no alert, ADS-B ICAO addr
    b[2], b[3], b[4] = (icao >> 16) & 0xFF, (icao >> 8) & 0xFF, icao & 0xFF
    b[5:8] = enc_ll(lat); b[8:11] = enc_ll(lon)
    a = 0xFFF if alt is None else (int((alt + 1000) / 25) & 0xFFF)
    b[11] = (a >> 4) & 0xFF
    b[12] = ((a & 0xF) << 4) | 0x9               # airborne + true-track
    b[13] = (11 << 4) | 10                        # NIC | NACp
    hv = 0xFFF if gs is None else (int(gs) & 0xFFF)
    vv = 0 if vs is None else (int(round(vs / 64)) & 0xFFF)
    b[14] = (hv >> 4) & 0xFF
    b[15] = ((hv & 0xF) << 4) | ((vv >> 8) & 0xF)
    b[16] = vv & 0xFF
    b[17] = 0 if trk is None else int((trk % 360) * 256 / 360) & 0xFF
    b[18] = cat
    b[19:27] = (call or '').ljust(8)[:8].encode('ascii', 'replace')
    b[27] = 0
    return bytes(b)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 4000)); sock.settimeout(0.5)
tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tx.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
outfh = open(OUTFILE, 'w') if OUTFILE else None

ref = [None, None]               # ownship ref for CPR; set at runtime from the device's own 0x0A (no hardcoded location)
ac = {}                          # icao -> dict(call,gs,trk,vs)
stats = {'pass': 0, 'traffic': 0, 'planes': set()}
def emit(fr):
    if DST: tx.sendto(fr, DST)
    if outfh: outfh.write(fr.hex() + '\n')

t = time.time()
while time.time() - t < DUR:
    try: d, _ = sock.recvfrom(4096)
    except socket.timeout: continue
    for part in d.split(b'\x7e'):
        if not part: continue
        de = destuff(part)
        if len(de) < 3: continue
        body = de[:-2]                  # strip incoming CRC
        mid = body[0]
        if mid in (0x00, 0x0A, 0x0B):   # pass standard messages through
            if mid == 0x0A and len(body) >= 11:
                def s24(x): v=(x[0]<<16)|(x[1]<<8)|x[2]; return v-0x1000000 if v&0x800000 else v
                la = s24(body[5:8]) * (180.0/2**23); lo = s24(body[8:11]) * (180.0/2**23)
                if la or lo: ref[0], ref[1] = la, lo
            emit(frame(body)); stats['pass'] += 1
        elif mid == 0x21 and len(body) >= 18:      # raw ADS-B traffic
            m = body[4:].hex()[:28]
            if len(m) < 28 or (int(m[:2], 16) >> 3) != 17: continue
            icao = int(m[2:8], 16); tc = int(m[8:10], 16) >> 3
            a = ac.setdefault(icao, {})
            try:
                if 1 <= tc <= 4:
                    a['call'] = pms.adsb.callsign(m).strip('_')
                elif tc == 19:
                    v = pms.adsb.velocity(m)
                    if v: a['gs'], a['trk'], a['vs'] = v[0], v[1], v[2]
                elif 9 <= tc <= 18:
                    if ref[0] is None:
                        continue          # no ownship reference yet -> can't CPR-decode; wait for 0x0A
                    alt = pms.adsb.altitude(m)
                    pos = pms.adsb.position_with_ref(m, ref[0], ref[1])
                    fr = make_0x14(icao, pos[0], pos[1], alt,
                                   a.get('gs'), a.get('trk'), a.get('vs'), a.get('call'))
                    emit(frame(fr)); stats['traffic'] += 1; stats['planes'].add(icao)
            except Exception:
                pass
        # 0x25 / 0x28 (proprietary status) dropped

print(f"passthrough={stats['pass']}  traffic_0x14_emitted={stats['traffic']}  "
      f"distinct_planes={len(stats['planes'])}", file=sys.stderr)
if outfh: outfh.close()
