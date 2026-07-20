# Sentry → standard-GDL90 transcoder

Turns a uAvionix **Sentry** (in `publicGDL90`/"compatibility" mode) into a
**standard GDL90 receiver** any EFB accepts (ForeFlight w/o Sentry lock, FltPlan
Go, DroidEFB, SkyDemon-over-GDL90, etc.).

## Why it's needed
In compatibility mode the Sentry emits:
- `0x00` Heartbeat, `0x0A` Ownship, `0x0B` Ownship geo-alt — **standard**, pass through.
- `0x21` — **proprietary**: a raw Mode S **DF17** ADS-B squitter wrapped as
  `21 ffffff <8D ICAO ME …>`. This is NOT standard GDL90 (a Stratux, Stratus, or
  SkyEcho 2 would emit decoded `0x14` Traffic Reports instead), so generic EFBs
  show ownship but **no traffic**.

`gdl90_transcode.py` decodes the `0x21` DF17 (pyModeS) and re-emits it as a
standard GDL90 **`0x14` Traffic Report**.

## Run (on a Pi joined to the Sentry Wi-Fi)
```bash
python3 -m venv ~/adsbvenv && ~/adsbvenv/bin/pip install "pyModeS<3"
# 1) enable public mode on the Sentry (one time, reversible):
curl -X POST -d '{"publicGDL90":true}' 'http://192.168.4.1/settings/?action=set'
# 2) transcode live to an EFB (unicast) or the LAN broadcast, on :4000:
~/adsbvenv/bin/python gdl90_transcode.py 999999 "" 192.168.4.255:4000
#   args: <seconds> [out_hexfile] [dst_ip:port]   (out_hexfile "" = none)
```
Point the EFB at the transcoder host (or let it hear the broadcast). Verify with
`show_gdl90.py` on the output.

**Verified 2026-07-20:** input Sentry stream → 77 `0x14` reports / 7 aircraft in
15 s, all CRC-valid, ICAOs/positions matching a same-moment piadsb SDR.

**Verified end-to-end 2026-07-20:** with the transcoder broadcasting to
`192.168.4.255:4000` on the Sentry's own AP, an iPad running **Garmin Pilot**
(joined to `SentryPlus_XXXX`) **displays the traffic**. The Sentry's built-in AP
does relay client broadcasts, so Option A (broadcast on the Sentry AP, no extra
hotspot) is sufficient. The iPad also receives the Sentry's raw `0x21` (which
Garmin ignores) plus our injected `0x14` (which it shows).

## 0x14 Traffic Report encoding (implemented here)
28-byte body: `14`, alert/addrtype, ICAO(3), lat(3, semicircle 2^23/180),
lon(3), alt(12b `(ft+1000)/25`)+misc, NIC|NACp, hVel(12b kt)+vVel(12b, 64fpm),
track(8b, 360/256), emitter cat, callsign(8 ASCII), emergency. Then GDL90
CRC-16 (LSB first) + `0x7E` framing with `7D`/`7E` byte-stuffing.

## Porting to ESP32 (future)
The Pi PoC uses pyModeS; an ESP32 build needs a **small C Mode S decoder** (no
Python). Portable pieces:
- **DF17 field extraction** — identity/callsign (TC1-4), airborne position
  (TC9-18) + altitude, velocity (TC19). dump1090's decoder is C and portable.
- **CPR position** — use *local/reference* CPR against ownship position (from the
  Sentry's `0x0A`), so no even/odd frame pairing/state needed. This is the key
  simplification that makes it ESP32-friendly.
- GDL90 CRC + `0x14` builder + byte-stuffing are trivial in C (see this file).
- Networking: ESP32 as STA on the Sentry AP + re-broadcast on :4000, or bridge to
  a second AP for the EFB. (This is the `esp32-projects/adsb-filter` target.)
