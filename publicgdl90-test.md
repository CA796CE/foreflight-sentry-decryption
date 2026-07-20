# Test: flipping `publicGDL90` (enable → verify → revert)

Goal: prove we can switch the Sentry from encrypted GDL90 (`0x25`/`0x26`) to
**standard plaintext GDL90** (`0x00` Heartbeat / `0x0A` Ownship / `0x14` Traffic)
by setting the `publicGDL90` flash parameter over HTTP, **verify** it worked from
the UDP stream, and **revert** it cleanly.

## Safety design
- **Revert channel is independent of the change:** `publicGDL90` only affects the
  GDL90 payload, not WiFi/HTTP, so `192.168.4.1:80` stays reachable to send the
  disable. We cannot lock ourselves out.
- **Observable = the UDP :4000 stream** captured on the sniffer host (a Sentry
  WiFi client). Encrypted baseline = only `0x25`/`0x26`. Success = standard IDs
  appear (`0x00`,`0x0A`,`0x14`,`0x0B`...).
- **Reversibility** rests on: (1) firmware setter is symmetric (same code writes
  the byte for enable/disable); (2) a harmless round-trip proven first (Stage 1);
  (3) factory-reset fallback with a saved `/settings` backup.
- Done on the bench, not in flight. Full `/settings` JSON backed up first.

## Set mechanism (from RE)
`POST /settings/?action=set`, `Content-Type: application/json`, body a partial
settings object. `publicGDL90` is a top-level flash-param key (sibling of `wifi`,
`ahrs`, `Power`, `coAlarmLevel`); value likely `"enable"`/`"disable"` (from the
firmware log strings) — will try that first, then `true`/`1`.

---

## Results log (2026-07-20) — SUCCESS

**`publicGDL90` works, is reversible, and needs no decryption key.** Setting it
`true` makes the Sentry emit standard, CRC-valid, plaintext GDL90 that any app
can decode.

### Stage 0 — baseline
- `/settings` backed up (572 B).
- Stream (6 s): `datagrams=24 frames_by_id={0x25:5, 0x26:45}` → encrypted only.

### Stage 1 — harmless write round-trip (proves write path + partial safety)
- `POST /settings/?action=set {"led":{"brightness":50}}` → **HTTP 200**.
- Diff vs baseline: **only `led.brightness` changed (37→50)** — no collateral
  changes. Partial JSON is respected (key-by-key dispatch).
- Restored to 37 → settings **identical to baseline**.

### Stage 2 — the flip

| POST body | HTTP | Stream (message IDs seen) | Result |
|---|---|---|---|
| `{"publicGDL90":"enable"}` (string) | 200 | `0x25,0x26` | **no-op** (string ignored) |
| `{"publicGDL90":true}` | 200 `Update successful` | `0x00,0x0a,0x0b,0x21,0x25` | **PLAINTEXT ✔** |
| `{"publicGDL90":1}` | 200 `Update successful` | `0x00,0x0a,0x0b,0x21,0x25,0x28` | **PLAINTEXT ✔** |
| `{"publicGDL90":false}` / `0` | 200 | `0x25,0x26` | **reverted ✔** |

So the value is a **boolean/int** (`true`/`1` = public, `false`/`0` = private);
the `"enable"`/`"disable"` strings from the firmware log are just how it *prints*
the bool, not the input format.

### Packets seen when public (`true`)
Standard GDL90 message IDs, all **CRC-valid**:
- `0x00` **Heartbeat**
- `0x0A` **Ownship report**
- `0x0B` **Ownship geometric altitude**
- `0x21` uAvionix message (frequent; now plaintext — likely AHRS/status)
- `0x25` device status (the one proprietary ID that persists)
- `0x28` (occasional)

Note `0x26` is **completely gone**. Decoding an 8 s raw capture: 6 Heartbeats + 6
Ownship reports parsed cleanly. Ownship lat/lon = 0 and callsign empty **only
because the Sentry had no GPS fix on the bench** (bench test, indoors) — the frame
structure decodes correctly; with a fix + traffic in view, `0x0A`/`0x14` carry
real positions and callsigns.

### Reversibility — proven
- `false`/`0` immediately returns the stream to `0x25`/`0x26`.
- Setter is symmetric (single global byte at DRAM `0x3ffb6c5c`), so enable/disable
  are the same code path — reversibility is structural.
- `/settings` JSON verified **identical to baseline** after the whole test.
- **Final state: device left encrypted** (`frames_by_id={0x25:3, 0x26:53}`) — as
  found. (Note: `publicGDL90` is a persistent flash param and is **not** in the
  `/settings` JSON, so a reboot would *not* revert it — always disable explicitly.)

### The one-liner that unlocks the device
```bash
# make it emit standard plaintext GDL90 (any EFB can read it):
curl -X POST -H 'Content-Type: application/json' \
     -d '{"publicGDL90":true}' 'http://192.168.4.1/settings/?action=set'
# revert to ForeFlight-encrypted:
curl -X POST -H 'Content-Type: application/json' \
     -d '{"publicGDL90":false}' 'http://192.168.4.1/settings/?action=set'
```

### GET vs POST — method is irrelevant, the JSON *body* is what matters
The handler dispatches on the `?action=set` query param and parses the request
**body** as JSON, ignoring the HTTP verb:

| Request | Result |
|---|---|
| `POST … -d '{"publicGDL90":true}'` | ✔ `Update successful` |
| `GET  … -d '{"publicGDL90":true}'` (GET **with body**) | ✔ `Update successful` |
| `GET  …?action=set&publicGDL90=true` (query param, no body) | ✖ HTTP 400 `JSON parse failed` |
| `GET  …?action=set&publicGDL90=1` | ✖ HTTP 400 `JSON parse failed` |

So a *plain* GET won't work, but a GET **carrying the JSON body** works exactly
like POST. Requirement = a JSON body, not the verb.

### Traffic comes as `0x21` = raw ADS-B (Mode S DF17), NOT standard `0x14`
In public/"compatibility" mode the Sentry emits **ownship** as standard GDL90
(`0x0A`/`0x0B`) + **Heartbeat** (`0x00`), but **traffic is delivered as `0x21`**:

```
0x21 body = 21 ffffff  +  8D <ICAO(3)> <ME(7)> <trailer>
                          └───────── raw Mode S DF17 extended squitter ─────────┘
```
uAvionix replaces the DF17 24-bit parity/CRC with their own trailer (so a strict
CRC check fails), but the `DF | ICAO | ME` body is a standard ADS-B message. Strip
the 4-byte `21 ffffff` prefix and decode the `8D…` with any Mode S decoder.

Verified live: 11 aircraft decoded (callsign/alt/lat/lon/gs/track), every ICAO
matching a same-moment piadsb (independent SDR) target — e.g. `ab761c`=ASA1322
FL380, `a40b41`=N36PJ 9925 ft, `a495bf`=DAL2167. Decode recipe (pyModeS **v2**;
v3 removed the per-field API):
```python
import pyModeS as pms
m = body[4:].hex()          # strip 21 ffffff -> "8d...."
if (int(m[:2],16)>>3)==17:  # DF17
    icao=m[2:8]; tc=int(m[8:10],16)>>3
    if 1<=tc<=4:  cs = pms.adsb.callsign(m)
    elif 9<=tc<=18: alt=pms.adsb.altitude(m); pos=pms.adsb.position_with_ref(m,LAT,LON)
    elif tc==19:  gs,trk,vr,_ = pms.adsb.velocity(m)
```
(978 UAT traffic, if present, likely arrives similarly under another uAvionix id.)

### Caveats
- Global toggle: affects **all** clients, so a co-connected ForeFlight would also
  receive plaintext (it reads standard GDL90 fine). ForeFlight never re-asserts
  private (confirmed by connection capture), so it should stick.
- Persists across reboot — always send `false` to restore.
- Tested against firmware **1.0.32** (RE was on 1.0.17); confirmed working live.
