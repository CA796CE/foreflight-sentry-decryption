#!/usr/bin/env python3
"""Is the traffic key TRANSMITTED during a ForeFlight session? Slide a 16-byte
window over the raw bytes of one or more FF<->Sentry capture files (pcap or hex)
and try each as an AES-128-ECB key vs the len=20 traffic ciphertext. If the key
is anywhere in the exchange (HTTP, UDP announce, websocket, ...), it decodes the
traffic. Entropy + optional ICAO/callsign oracle from a public capture.

  pcap_keyhunt.py <secure_capture.hex> <session.pcap> [more.pcap ...] [--public <public.hex>]
"""
import argparse

from Crypto.Cipher import AES

import common

ap = argparse.ArgumentParser()
ap.add_argument("secure_capture")
ap.add_argument("sessions", nargs="+", help="FF-session capture files (raw bytes scanned)")
ap.add_argument("--public", help="public-mode capture for the ICAO/callsign oracle")
a = ap.parse_args()

oracle = common.build_oracle(a.public)
KNOWN = oracle["icaos"]
LONG = [b for _, b in oracle["long_cribs"]]

L20 = common.load_len20(a.secure_capture)
blob = b"".join(c[2:18] for c in L20[:150])

best, crib_hits, icao_hits = [], [], []
for pf in a.sessions:
    data = open(pf, "rb").read()
    print(f"{pf}: {len(data)} bytes -> {len(data) - 15} windows", flush=True)
    for koff in range(len(data) - 15):
        dec = AES.new(data[koff:koff + 16], AES.MODE_ECB).decrypt(blob)
        e = common.entropy(dec)
        if e < 7.4:
            best.append((e, pf, koff, data[koff:koff + 16].hex()))
        if e < 7.5:
            for c in LONG:
                if c in dec:
                    crib_hits.append((pf, koff, round(e, 3)))
            for ic in KNOWN:
                if ic in dec:
                    icao_hits.append((pf, koff, ic.hex(), round(e, 3)))
best.sort()
print("\n== lowest-entropy key candidates from session bytes ==")
for e, pf, koff, kh in best[:15]:
    print(f"  entropy={e:.3f} {pf.split('/')[-1]}@{koff} key={kh}")
if not best:
    print("  (none below 7.4 -> no window makes the traffic structured)")
print("\n== callsign-crib hits ==", crib_hits[:20] or "none")
print("== ICAO hits ==", icao_hits[:20] or "none")
if not best and not crib_hits:
    print("\nVERDICT: the traffic key is NOT present in the session bytes -> not "
          "exchanged over the wire (baked into the app, or capture incomplete).")
