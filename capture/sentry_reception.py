#!/usr/bin/env python3
"""Quick reception probe: are we connected, and is real traffic overhead?

Read-only, writes no file, does NOT change the device mode. Use it before
spending a full capture window (sentry_capture.py) to confirm the moment is
worth capturing.

It sends the ForeFlight-style discovery announce (so the Sentry unicasts GDL90
to us), listens a few seconds, and decrypts the 0x26 stream with the known key:
  * seeing ownship messages (0x28 AHRS / 0x27 GPS)  -> connected & streaming
  * seeing an inner 0x21 DF17 (21 ff ff ff 8D/8F …) -> REAL TRAFFIC overhead

The /data/ HTTP endpoint is only a stored-log directory index, not a live rate,
so this decrypt-based probe is the reliable signal.

  python3 sentry_reception.py [--device 192.168.4.1] [--seconds 8]

Needs pycryptodome. Independent cross-check: your own SDR (piadsb).
"""
import socket, sys, time

DEVICE = "192.168.4.1"
SECONDS = 8
KEY_HEX = "a6b1c01f2200566268937c708a06ddcf"   # AES-128-ECB, null IV
argv = sys.argv[1:]
if "--device" in argv:
    i = argv.index("--device"); DEVICE = argv[i + 1]; del argv[i:i + 2]
if "--seconds" in argv:
    i = argv.index("--seconds"); SECONDS = int(argv[i + 1]); del argv[i:i + 2]

try:
    from Crypto.Cipher import AES
    KEY = bytes.fromhex(KEY_HEX)
except Exception:
    print("[recv] needs pycryptodome:  pip install pycryptodome", file=sys.stderr)
    sys.exit(2)

def decrypt_0x26(content):            # content: destuffed, CRC-stripped, starts 26 00
    n = (len(content) - 2) // 16      # last ~18B is a plaintext trailer, not encrypted
    if n <= 0:
        return b""
    return AES.new(KEY, AES.MODE_ECB).decrypt(bytes(content[2:2 + 16 * n]))

def destuff(p):
    o = bytearray(); i = 0
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

ANNOUNCE = b'{"App":"ForeFlight","GDL90":{"port":4000}}'
ann = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ann.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
def announce():
    for dst in ("255.255.255.255", DEVICE):
        try: ann.sendto(ANNOUNCE, (dst, 63093))
        except Exception: pass

rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
rx.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
rx.bind(("0.0.0.0", 4000)); rx.settimeout(0.5)

print(f"[recv] probing {DEVICE} for {SECONDS}s…", file=sys.stderr)
dgrams = own = traffic = 0
t0 = last_ann = 0.0
t0 = time.time()
while time.time() - t0 < SECONDS:
    if time.time() - last_ann >= 2.0:
        announce(); last_ann = time.time()
    try:
        d, _ = rx.recvfrom(8192)
    except socket.timeout:
        continue
    dgrams += 1
    for part in d.split(b"\x7e"):
        if not part:
            continue
        de = destuff(part)
        if len(de) < 3:
            continue
        body = de[:-2]
        if body[0] != 0x26:
            continue
        pt = decrypt_0x26(body)
        if not pt:
            continue
        if pt[0] in (0x28, 0x27):
            own += 1
        if pt[:4] == b"\x21\xff\xff\xff" and len(pt) >= 5 and pt[4] in (0x8D, 0x8F):
            traffic += 1

print("\n==== reception ====")
if dgrams == 0:
    print("NO STREAM — got 0 datagrams. Check you are joined to the Sentry AP and "
          "can reach the device (ping 192.168.4.1).")
    sys.exit(3)
print(f"datagrams        : {dgrams}")
print(f"ownship (0x28/27): {own}   -> {'connected & streaming' if own else 'stream up but no ownship?'}")
print(f"traffic (0x21)   : {traffic}")
print("-> " + ("TRAFFIC OVERHEAD — good time to capture (sentry_capture.py)."
               if traffic else
               "no traffic decoded — Sentry hears no aircraft here (or traffic uses "
               "a non-0x21 format; if aircraft are definitely overhead per your SDR, "
               "capture anyway and let step 2 analyze it)."))
