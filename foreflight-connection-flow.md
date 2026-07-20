# What a ForeFlight → Sentry connection looks like

Captured 2026-07-20 by passive 802.11 monitor (Atheros AR9271, monitor mode,
channel 1) sniffing the **open** `SentryPlus_XXXX` AP, plus an earlier on-host
capture. The AP has no encryption, so all payloads below are real bytes off the
air. Roles:

- **Sentry** (AP + server): `192.168.4.1`
- **iPad / ForeFlight** (client): `192.168.4.2`, UA `ForeFlight/XXXXXX CFNetwork/XXXX Darwin/XX.X.X`
- Other observed clients: `192.168.4.3` (our sniffer-host sniffer's managed iface), `192.168.4.4`

There is **no websocket, no authentication, and no encryption of the control
channel** — it's plain HTTP/1.1 on port 80 plus UDP. (The firmware *has*
websocket + Digest-auth code, but ForeFlight does not use it on connect.)

---

## Sequence overview

```
1. Wi-Fi association     iPad joins open AP SentryPlus_XXXX (channel 1)
2. App-announce (UDP)    iPad ──broadcast :63093──► "{...App:ForeFlight,GDL90:{port:4000}}"
3. HTTP status/config    iPad ──GET :80──► /?action=get , /settings/?action=get
4. HTTP data/stats       iPad ──POST/GET :80──► /data , /data/  (log index + stats stream)
5. GDL90 data (UDP)      Sentry ──unicast :4000──► iPad   (GDL90 frames, ENCRYPTED 0x25/0x26)
```

Steps 2–4 repeat/refresh; step 5 is the continuous data plane.

---

## 1. Wi-Fi association

iPad associates to the open ESS `SentryPlus_XXXX` (BSSID `AA:BB:CC:DD:EE:FF`,
2.4 GHz ch 1, no PRIVACY bit → **open**). The Sentry's softAP hands out
`192.168.4.x` via DHCP.

## 2. Device discovery — UDP broadcast to port 63093

ForeFlight announces itself (and the UDP port it wants GDL90 on) with a broadcast
datagram to `255.255.255.255:63093`. Two forms were seen from `192.168.4.2:49255`:

```json
{"App":"ForeFlight","GDL90":{"port":4000}}
```
(42 bytes — **this exact string is what the Sentry firmware `memcmp`s**, see
FRAME-ANALYSIS / README) and a richer form:
```json
{"Version":"XX.X.X","GDL90":{"port":4000},"App":"ForeFlight","DeviceName":"<redacted-efb>"}
```

The firmware recognizes `ForeFlight` and `Flite Deck Pro` templates; both map to
GDL90 on port 4000. This announce tells the Sentry **where** to send GDL90 — it
does **not** select encrypted vs. plaintext.

## 3. HTTP status + settings reads (port 80)

Immediately on (re)connect the app opens several short-lived HTTP/1.1
connections to `192.168.4.1:80`. Request headers (typical):

```
GET /?action=get HTTP/1.1
Host: 192.168.4.1
Accept: */*
Accept-Language: en-US,en;q=0.9
Connection: keep-alive
Accept-Encoding: gzip, deflate
User-Agent: ForeFlight/XXXXXX CFNetwork/XXXX Darwin/XX.X.X
```

**`GET /?action=get`** → device status:
```
HTTP/1.1 200 OK
Server: Mongoose/6.11
Content-Type: application/json
Content-Length: 213

{"wifiVersion":"1.0.32-SentryPlus","ssid":"SentryPlus_XXXX","clientCount":2,
 "stationSsid":"SkyView-XXXXX","stationState":5,"adsbVersion":"2.4.44 : 2.6.14",
 "serialNumber":"XXXXXXXXXX : XXXXXXXXXX","coredump":false}
```

**`GET /settings/?action=get`** → full settings (Content-Length 572):
```json
{"client":{"autoConnect":false,"ssid":"SkyView-XXXXX","security":true},
 "wifi":{"stationState":5,"ssid":"SentryPlus_XXXX","hidden":false,"security":false,
         "dirty":false,"channel":0,"power":9,"operationalChannel":1},
 "led":{"brightness":37,"auto":false},
 "ahrs":{"orientation":[{"source":0,"reverse":false},{"source":1,"reverse":false},
         {"source":2,"reverse":false}],"offset":[0,0,0],
         "autoLevel":true,"kp":0.1,"ki":0,"glim":0.15,"tlim":2,"galpha":1,"aalpha":0.2},
 "coAlarmLevel":200,"Power":{"autoOnEnabled":false,"powerSavings":false}}
```

Note: **`publicGDL90` is not present** in either response — it is not exposed
over HTTP, and ForeFlight never writes it.

## 4. HTTP `/data` — log index + stats stream (port 80)

```
POST /data HTTP/1.1        Content-Length: 0          → HTTP/1.1 301 Moved  (Location: /data/)
GET  /data/ HTTP/1.1                                   → 301 → 200 text/html, Transfer-Encoding: chunked
```

`GET /data/` returns an HTML **"Index of /data/"** directory listing (Mongoose
file index with a sortable-table script). ForeFlight then pulls a
**`text/plain` stats stream** — a CSV whose header is the device's internal
telemetry columns, e.g.:

```
Host::positionAccuracy_mm, Host::verticalAccuracy_mm, Host::velocityAccuracy_mmps,
Host::UATLongPkts, Host::1090esPkts, Host::UplinkPkts,
Host::UATLongPktsPerSec, Host::1090ESPktsPerSec, Host::UplinkPktsPerSec, ...
```
followed by numeric rows (timestamps, packet counts, GPS accuracy, IMU values,
etc.). This is diagnostics/telemetry, **not** the traffic picture.

## 5. GDL90 data plane — UDP to port 4000 (ENCRYPTED)

The actual ADS-B / ownship / AHRS data is sent as **UDP unicast from the Sentry
(`192.168.4.1`) to the app's IP on port 4000**, GDL90-framed (`0x7E` flag,
byte-stuffing, CRC-16 — 100% CRC-valid). But the payload is **encrypted**: only
two proprietary message IDs appear —

- `0x25` — static device/status frame (constant)
- `0x26` — encrypted live payload (traffic/ownship/status), 16-byte AES blocks,
  ECB-mode leakage; no plaintext.

ForeFlight decrypts it (licensed key). See `README.md` / `FRAME-ANALYSIS.md`.
This stream begins essentially as soon as the app announces on :63093 (step 2)
and is the "receiving data from the device" end state.

---

## What is NOT in the flow (notable negatives)

- **No websocket** (`Upgrade: websocket` never seen) — despite firmware support.
- **No authentication** on any request (no `Authorization`, no Digest challenge).
- **No `publicGDL90` / `action=set`** — ForeFlight never sets the encryption mode;
  `publicGDL90=false` (encrypted) is simply the persistent device default.
- **No TLS** — everything is plaintext HTTP/UDP on an open AP.

### Implication

Because ForeFlight only *reads* status and *announces* itself, a third-party app
can reproduce the whole client side trivially (send the :63093 announce, read
`/?action=get`). The only barrier to usable data is the encrypted `0x26`
payload — which the device itself can emit in the clear if `publicGDL90` is set
(see README, path #1).

---

*Artifacts: `~/tmp/ws2.pcap` (monitor capture), `~/tmp/ff_connect_flow.txt`,
`~/tmp/ws_clean.txt`. Capture method: `iw dev wlan1 set type monitor` +
`tcpdump -i wlan1 'type data and wlan host aa:bb:cc:dd:ee:ff'`.*
