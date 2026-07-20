# foreflight-sentry-decryption

**Goal: make a uAvionix Sentry / Sentry Plus usable outside of ForeFlight.**

The Sentry is a capable portable ADS-B / GPS / AHRS receiver, but uAvionix
deliberately locks it to ForeFlight (iOS only). It broadcasts its data as
**GDL90-framed UDP on port 4000**, but the useful messages are **encrypted**, so
no third-party EFB can use the device. This repo documents an effort to
understand that scheme and find a legitimate way to get usable data out —
ideally by flipping the device's own **`publicGDL90`** (unencrypted) mode rather
than by breaking any cryptography.

> Status: research / reverse-engineering in progress. Nothing here breaks
> encryption; the most promising result is a **plaintext ("public") GDL90 mode
> that already exists in the firmware.**

## The problem, precisely

- Sentry sends UDP **unicast to each connected client on `:4000`**, standard
  GDL90 framing (`0x7E` flag, byte-stuffing, CRC-16). Framing verified: **100%
  of frames pass the GDL90 CRC** (Garmin table form
  `crc = Table[crc>>8] ^ (crc<<8) ^ byte`).
- But instead of the standard message IDs (`0x00` Heartbeat, `0x0A` Ownship,
  `0x14` Traffic), the stream contains only **two proprietary IDs**:
  - **`0x25`** — a *static* device/status frame (byte-for-byte constant).
  - **`0x26`** — the *encrypted* live payload (traffic / ownship / status).
- ForeFlight can display traffic (several targets observed) because
  uAvionix licenses it the decryption. Every other app sees only opaque `0x26`.

### Evidence the `0x26` payload is encrypted
- Dynamic region entropy **7.5–7.75 bits/byte**, all **256/256 byte values**,
  **zero plaintext** (no ASCII callsigns/altitudes to match with heuristics).
- Content lengths are **quantized** (18/20/45/68 …) and everything lands on
  **16-byte (AES) boundaries**. The 68-byte subtype decomposes as:
  `26 00` + 32 B ciphertext + 16 B low-entropy field + **18 B constant trailer**.
- Exact 16-byte ciphertext blocks **recur** across independent frames — an
  **ECB-mode fingerprint** (identical plaintext → identical ciphertext). Rules
  out CTR / CBC-with-random-IV; a pairwise-XOR test rules out a simple XOR
  scramble.
- **Firmware confirms it:** the log string `Failed to encrypt/stuff GDL90
  message` is present. It uses **mbedtls** (ESP32 hardware AES).

Silver lining: the ECB leakage lets you **count / fingerprint aircraft without
the key** (distinct recurring blocks ≈ distinct targets) — a useful cross-check
against a known ADS-B source.

## The key discovery: `publicGDL90`

The firmware contains a runtime flag **`publicGDL90`** (log: `Setting publicGDL90
to %s`) and an **app-identification handshake** over a **websocket** control
channel. Recognized apps are embedded as JSON templates:

```json
{"App":"ForeFlight","GDL90":{"port":4000}}
{"App":"Flite Deck Pro","GDL90":{"port":4000}}
```

**If we can drive the device into `publicGDL90 = true`, the encryption problem
disappears entirely — no key needed.** This is the preferred path.

### What the firmware reverse-engineering shows (v1.0.17, classic ESP32 / Xtensa)

Disassembled with `xtensa-esp32-elf-objdump`; addresses below are from the
plaintext OTA image.

- **The app handshake does *not* pick the encryption mode.** The handler at
  `0x400e121c` does an exact `memcmp` of the incoming websocket JSON against the
  two templates (ForeFlight = 42 bytes, Flite Deck Pro = 46 bytes) and **both
  recognized apps branch to the *same* code** (`0x400e1255`). So identifying as
  Flite Deck Pro does **not** flip anything — it just validates "known app."
- **`publicGDL90` is a persistent `FLASH_PARAMETERS` config key**, set through a
  string-keyed config dispatch (sequential key compares at `0x400e5100+`). Its
  siblings in that table are `wifi`, `ahrs`, `Power`, `coAlarmLevel`, `tests`,
  `operationalChannel` — **the same top-level keys returned by
  `GET /settings/?action=get`.** So the same JSON config handler almost
  certainly accepts `publicGDL90`, even though `?action=get` doesn't report it
  (hidden/undocumented key).
- **Setter (`0x400e5145`–`0x400e516e`):** on key match it parses the value,
  **stores one byte to the global at DRAM `0x3ffb6c5c`**, and logs
  `Setting publicGDL90 to enable|disable`. It's a **single device-global byte**,
  and being a FLASH parameter it is expected to **persist across reboot**.

### Answers to the key questions

- **How to flip it:** most likely `POST /settings/?action=set` with body
  `{"publicGDL90":"enable"}` (or `true`/`1`) — the same endpoint/handler used for
  the other flash parameters. (Serial console is the other setter, but the USB-C
  port is charge-only, so that needs case entry.) **Not yet tested — this is a
  write, and testing has been kept non-destructive so far.**
- **ForeFlight first, then a "public" set:** because `publicGDL90` is a single
  global (not per-connection) and the connection handshake never writes it,
  setting it to `enable` switches the **whole device** to standard unencrypted
  GDL90 for **all** clients — ForeFlight included (it reads standard GDL90
  natively). Statically, nothing in the connect path re-asserts private, and the
  value persists in flash, so it should **stick**. The one unknown is whether the
  ForeFlight *app* proactively issues its own config-set to force
  `publicGDL90=disable` on connect — observable by capturing the websocket
  traffic when ForeFlight attaches.

> Caveat: RE was done on v1.0.17; the deployed device runs v1.0.32. The mechanism
> is expected to hold but exact key/paths should be reconfirmed.

## Device / firmware facts

- **MCU:** classic **ESP32** (Xtensa LX6, image `chip_id=0`).
- **Firmware project:** `pingESP32` (uAvionix), built with **ESP-IDF v4.2**,
  **mbedtls**, **Mongoose 6.11** web server, Boost 1.64. Dev path leaks:
  `.../pingESP32_Alonzo_SentryPlus/...`.
- **Flash encryption is OFF** — the OTA image is plaintext: valid `0xE9` app
  magic, readable `esp_app_desc` at offset 0x20, normal structured/low-entropy
  regions. So the AES key and crypto routines are **present in the firmware
  image** and recoverable by static RE if the handshake route fails.
- **USB-C is charge-only** — verified non-destructively: plugged into macOS and a
  Raspberry Pi with two cables (one confirmed data), device on → **zero USB
  enumeration** on either host. No `espefuse`/UART access without opening the
  case.

## Web server endpoint map (Mongoose, `http://192.168.4.1/`)

Confirmed live (read-only GET) and/or found in firmware. **Write/action
endpoints were NOT exercised.**

| Endpoint | Method | Purpose |
|---|---|---|
| `/` | GET | Landing page (`index_Sentry.html`); `GET /?action=get` → status JSON (versions, ssid, clientCount, serials) |
| `/settings` | GET | `settings_Sentry.html` config UI |
| `/settings/?action=get` | GET | **(read)** full settings JSON: AP wifi, client wifi, LED, AHRS cal, CO alarm, power |
| `/settings/?action=set` | POST | **(write)** apply settings / factory reset — *not used* |
| `/calibration` | GET/POST | AHRS calibration |
| `/coredump` | GET | Core dump download (only when `coredump==true`; could leak RAM/keys) |
| `/connect` | ? | WiFi station connect (action) |
| `/disassoc` | ? | WiFi disassociate (action) |
| `/ap`, `/address`, `/bssid` | ? | WiFi AP / addressing info |
| `/espUpdate` | POST | ESP32 firmware OTA (this is how the `.bin` is pushed) |
| `/pingUpdate` | POST | Update the internal ADS-B "target" module over UART |
| `/dev/uart`, `/dev/uart/0` | — | VFS console/UART (internal) |
| websocket (`Upgrade: websocket`) | WS | **Control channel** — app identification + `publicGDL90`; HTTP Digest auth (`WWW-Authenticate: Digest qop="auth"`) |

`?action=get` = read, `?action=set` = write (per the settings page JS).

## Paths to "usable outside ForeFlight" (ranked)

1. **Flip `publicGDL90` via the websocket handshake** *(best — no crypto).*
   Reverse the app-identity/`auth` logic and send whatever a "public" app sends.
2. **Set `publicGDL90` via the config key-value system** if it's directly
   settable (console/websocket/HTTP).
3. **Extract the AES key** from the plaintext firmware image (mbedtls + hardcoded
   key) and write a standalone decoder. Feasible since flash encryption is off;
   the key is almost certainly **global** (one extraction unlocks all Sentries).
4. **Frida hook of ForeFlight on iOS** — dumps key *and* the decrypted format at
   runtime; needs a jailbroken/instrumentable device.

Brute-forcing the cipher is **not** a path: a real 128-bit key is ~10¹³–10²¹
years even with extreme hardware. Only a *derived* (serial/MAC) key would be
brute-forceable, and that still requires reversing the derivation.

## Sources / artifacts

- **Extracted firmware (v1.0.17) + captured update request** — dimme.net, who
  sniffed the OTA transfer:
  <https://dimme.net/foreflight-sentry-firmware-v1-0-17/> (file
  `Sentry_V1.0.17.bin`). Our device runs v1.0.32; the key is expected to be
  common across versions.
- **Prior art — reversing the sibling "Scout" receiver** (hit the same
  `0x25`/`0x26` wall, no public break):
  <https://cbpowell.wordpress.com/2025/09/25/reversing-the-scout-ads-b-receiver-part-1/>
- **ForeFlight GDL90 extended spec** (documents *their* `0x65` message, not
  uAvionix `0x25`/`0x26`): <https://www.foreflight.com/connect/spec/>
- **uAvionix Sentry is ForeFlight-only** (background):
  <https://support.uavionix.com/hc/en-us/articles/48078883059859-ForeFlight-Sentry-FAQs>

## Legal / ethical note

This is interoperability research on a device we own, to use our own hardware
with our own software. It does not redistribute uAvionix/ForeFlight code or keys.
Extracting keys from the app or firmware may implicate DMCA §1201 and app ToS;
the `publicGDL90` route uses the device's *own* documented capability and is the
cleanest option. Do not use decoded data for anything the FAA would frown on;
ADS-B is safety-of-life data.
