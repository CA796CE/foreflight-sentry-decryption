#!/usr/bin/env python3
"""Step 1 capture tool: grab a SECURE-mode Sentry :4000 stream to disk.

Goal of the capture: get `0x26` (encrypted) frames while the Sentry is
actually hearing real ADS-B traffic, so the decrypted payload will contain a
*traffic* message (hypothesized: an inner `0x21` raw Mode S DF17), not just
ownship/AHRS. See ../encrypt-mode-traffic.md.

What it does:
  1. (optional) forces SECURE mode  -> POST {"publicGDL90":false}
  2. captures every UDP :4000 datagram to a timestamped hex file (one line per
     datagram: `<epoch> <hex>`), so nothing has to be recaptured.
  3. tallies OUTER GDL90 frame IDs and WARNS if anything other than 0x25/0x26
     shows up (means it is not actually in secure mode).
  4. decrypts 0x26 live with the known key and tallies INNER message IDs, so
     you get an immediate on-screen signal the moment a traffic message
     (inner 0x21 / a DF17) appears -- that is the capture you are hunting for.

Run on a Pi/laptop joined to the Sentry Wi-Fi:
  python3 sentry_capture.py 120 capture.hex
  args: <seconds> [out_hexfile] [--no-set] [--device 192.168.4.1]

pip install pycryptodome   (for the live decrypt peek; capture still works
without it -- it just skips the inner tally).
"""
import socket, sys, time, urllib.request, json

DEVICE = "192.168.4.1"
KEY_HEX = "a6b1c01f2200566268937c708a06ddcf"   # AES-128-ECB, null IV (see firmware-crypto-notes.md)

# ---- args ----
argv = sys.argv[1:]
NO_SET = "--no-set" in argv
argv = [a for a in argv if a != "--no-set"]
if "--device" in argv:
    i = argv.index("--device"); DEVICE = argv[i + 1]; del argv[i:i + 2]
DUR = int(argv[0]) if argv else 120
OUTFILE = argv[1] if len(argv) > 1 else f"sentry_secure_{int(time.time())}.hex"

# ---- optional AES (live inner-ID peek) ----
try:
    from Crypto.Cipher import AES
    KEY = bytes.fromhex(KEY_HEX)
    def decrypt_0x26(content):        # content: destuffed, CRC-stripped, starts 26 00
        n = (len(content) - 2) // 16  # last ~18B is a plaintext trailer, not encrypted
        if n <= 0:
            return b""
        return AES.new(KEY, AES.MODE_ECB).decrypt(bytes(content[2:2 + 16 * n]))
except Exception:
    decrypt_0x26 = None
    print("[warn] pycryptodome not installed -> skipping live inner-ID decrypt peek "
          "(capture to disk still works).", file=sys.stderr)

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

def force_secure():
    url = f"http://{DEVICE}/settings/?action=set"
    body = json.dumps({"publicGDL90": False}).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            print(f"[set] publicGDL90=false -> HTTP {r.status} {r.read(64)!r}", file=sys.stderr)
    except Exception as e:
        print(f"[set] WARNING could not set secure mode: {e}", file=sys.stderr)

if not NO_SET:
    force_secure()
    time.sleep(1.0)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(("0.0.0.0", 4000))
sock.settimeout(0.5)
outfh = open(OUTFILE, "w")

# The Sentry only unicasts GDL90 to clients that have ANNOUNCED themselves
# (ForeFlight-style discovery, see foreflight-connection-flow.md). A fresh
# client IP gets nothing until it sends this, so we broadcast it periodically.
# The firmware only recognizes the ForeFlight / Flite Deck Pro templates, so
# the string must match one exactly. This selects the GDL90 port, NOT the
# encryption mode (publicGDL90 is separate).
ANNOUNCE = b'{"App":"ForeFlight","GDL90":{"port":4000}}'
ann_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ann_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
def announce():
    for dst in ("255.255.255.255", DEVICE):
        try:
            ann_sock.sendto(ANNOUNCE, (dst, 63093))
        except Exception:
            pass

outer = {}          # outer GDL90 id -> count
inner = {}          # decrypted inner id -> count
traffic_hits = 0    # inner frames that look like a DF17 traffic message
datagrams = 0
t0 = time.time()
last_report = t0
last_announce = 0.0
print(f"[cap] writing {OUTFILE}, {DUR}s, device {DEVICE}"
      f"{' (mode unchanged)' if NO_SET else ''}", file=sys.stderr)

try:
    while time.time() - t0 < DUR:
        if time.time() - last_announce >= 2.0:   # keep the stream flowing
            announce()
            last_announce = time.time()
        try:
            d, _ = sock.recvfrom(8192)
        except socket.timeout:
            pass
        else:
            datagrams += 1
            outfh.write(f"{time.time():.3f} {d.hex()}\n")
            for part in d.split(b"\x7e"):
                if not part:
                    continue
                de = destuff(part)
                if len(de) < 3:
                    continue
                body = de[:-2]                      # strip outer CRC
                mid = body[0]
                outer[mid] = outer.get(mid, 0) + 1
                if mid == 0x26 and decrypt_0x26:
                    pt = decrypt_0x26(body)
                    if pt:
                        iid = pt[0]
                        inner[iid] = inner.get(iid, 0) + 1
                        # Traffic signal, STRICT to avoid false positives from
                        # the trailer/multi-block noise: the hypothesized
                        # encrypted-traffic frame is a public-mode 0x21 verbatim,
                        # i.e. `21 ff ff ff  8D/8F <icao> …` (DF17/18, CA-carrying).
                        # This exact 5-byte signature has ~0 chance of appearing by
                        # chance across a capture, so a hit is almost surely real.
                        # (If real traffic turns out to use another format, step 2's
                        # offline ICAO-match search catches it -- the live tool just
                        # errs toward NOT claiming traffic.)
                        if (pt[:4] == b"\x21\xff\xff\xff"
                                and len(pt) >= 5 and pt[4] in (0x8D, 0x8F)):
                            traffic_hits += 1
        # periodic status line
        now = time.time()
        if now - last_report >= 5:
            last_report = now
            bad = {k: v for k, v in outer.items() if k not in (0x25, 0x26)}
            warn = f"  !! NON-SECURE IDs {[hex(k) for k in bad]}" if bad else ""
            innerstr = " ".join(f"{hex(k)}:{v}" for k, v in sorted(inner.items()))
            print(f"[{int(now - t0):3d}s] dgrams={datagrams} "
                  f"outer={{{' '.join(f'{hex(k)}:{v}' for k,v in sorted(outer.items()))}}} "
                  f"inner={{{innerstr}}} traffic_hits={traffic_hits}{warn}",
                  file=sys.stderr)
finally:
    outfh.close()

# ---- final summary ----
bad = {k: v for k, v in outer.items() if k not in (0x25, 0x26)}
print("\n==== capture summary ====", file=sys.stderr)
print(f"file            : {OUTFILE}  ({datagrams} datagrams)", file=sys.stderr)
print(f"outer frame ids : {{{' '.join(f'{hex(k)}:{v}' for k,v in sorted(outer.items()))}}}",
      file=sys.stderr)
if bad:
    print(f"** NOT SECURE ** saw {[hex(k) for k in bad]} -> device was in public mode; "
          f"re-run without --no-set (or POST publicGDL90:false).", file=sys.stderr)
elif set(outer) <= {0x25, 0x26}:
    print("secure mode OK  : only 0x25/0x26 present.", file=sys.stderr)
if decrypt_0x26:
    print(f"inner (decrypted): {{{' '.join(f'{hex(k)}:{v}' for k,v in sorted(inner.items()))}}}",
          file=sys.stderr)
    if traffic_hits:
        print(f"*** TRAFFIC FOUND: {traffic_hits} inner DF17/0x21 frames -> "
              f"THIS is the capture to keep. Feed {OUTFILE} to step 2. ***", file=sys.stderr)
    else:
        print("no inner DF17/0x21 seen -> Sentry likely heard no traffic. Move it to "
              "sky-view (confirm reception with sentry_reception.py) and recapture.",
              file=sys.stderr)
