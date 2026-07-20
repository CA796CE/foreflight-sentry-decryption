# Finding traffic in encrypt (`0x26`) mode

**Goal:** with the device left *secure* (`publicGDL90=false`), recover **traffic**
(other aircraft) from the encrypted `0x26` stream using the AES key
`a6b1c01f2200566268937c708a06ddcf` (AES-128-ECB, null IV).

## Status: method ready, **traffic not yet captured in encrypt mode**

Every secure-mode capture so far has been **indoors, where the Sentry receives
≈0 ADS-B** (its Heartbeat "messages received" counter reads 0). So the `0x26`
stream we've decrypted contains only **ownship** messages, not traffic:

| decrypted id | rate | what it is |
|---|---|---|
| `0x28` (64 B) | ~6 Hz | **AHRS** — signed LE values (roll/pitch/yaw, accel/gyro) + a constant 16-B device signature |
| `0x27` (32 B) | ~1 Hz | **GPS/ownship dynamics** — header `27 03`, a sequence counter, fix data |
| `0x25` (16 B) | ~1 Hz | static **device status/ID** |

Decrypting an indoor `0x26` capture gives `0x28`×191, `0x27`×27, `0x25`, and a
handful of singletons that are just mis-aligned block tails (a stray `0x21` first
byte did **not** decode as a valid DF17 — it was noise, not traffic).

## Hypothesis (strong, unconfirmed): encrypted traffic → `0x21` raw ADS-B

Public/compatibility mode delivers traffic as **`0x21` = a raw Mode S DF17**
(`21 ffffff 8D <ICAO> <ME>`). Secure mode wraps *the same* GDL90 message set in
`0x26`+AES. So encrypted traffic should simply be **`0x26` that decrypts to a
`0x21`** frame — identical format, just behind the cipher. We just have never had
**secure mode + real traffic at the same time** (outside runs were all in public
mode for the Garmin test; secure runs were all indoors).

## Validation plan (the one missing capture)

1. Put the Sentry where it **hears traffic** (window/outside — confirm its
   Heartbeat msg-count goes > 0, or cross-check piadsb sees aircraft).
2. Ensure **secure** mode: `POST {"publicGDL90":false}`; verify the stream is
   `0x25`/`0x26` only (no `0x21`, no `0x0a`).
3. Capture `0x26`, **decrypt every frame**, and look for the traffic message:
   - **Primary test:** decrypt starts with `0x21` and byte[4] is a DF17 marker
     (`8D`/`8F` → `>>3 == 17`); strip `21 ffffff`, decode the DF17 with pyModeS.
   - **Fallback (format-agnostic):** search each decrypted frame's bytes for an
     **ICAO address that matches a same-moment piadsb target** — that pins the
     traffic message type and the ICAO field offset even if it isn't `0x21`.
4. Cross-check decoded callsign/altitude/position against piadsb to confirm.

## Decode / transcode recipe (once confirmed)

Same pipeline as the public-mode transcoder, with a **decrypt step in front**:
```python
from Crypto.Cipher import AES
KEY = bytes.fromhex('a6b1c01f2200566268937c708a06ddcf')
def decrypt_0x26(content):                 # content: destuffed, CRC-stripped, starts 26 00
    n = (len(content) - 2) // 16
    return AES.new(KEY, AES.MODE_ECB).decrypt(content[2:2+16*n])
# if decrypt starts 0x21: raw = dec[4:]; DF17-decode raw[:14] (pms.adsb.*)
# then optionally emit as standard GDL90 0x14 (see transcoder/) so any EFB shows it
```
This yields an **encrypt-mode transcoder**: decrypt `0x26` → extract `0x21`
traffic → re-emit standard `0x14`. It makes an **unmodified, still-secure**
Sentry usable by any EFB — the key-based counterpart to the public-mode path.

## Open items
- Capture the one **secure + sky-view** window to confirm `0x26`→`0x21` traffic.
- Decode the `0x28` (AHRS) / `0x27` (GPS) ownship fields (separate effort; see the
  controlled-stimulus plan) — bonus attitude + GPS source.
- Verify whether the AES block layout for the big frames leaves a plaintext
  trailer vs. all-encrypted (affects exactly how many blocks to decrypt).

## Artifacts
- Key + brute-force method: `firmware-crypto-notes.md`
- Public-mode transcoder (the `0x21`→`0x14` half): `transcoder/`
- Captures: `~/tmp/sec_traffic*.hex` (indoor, no traffic), `~/tmp/datagrams.hex`
  (indoor secure, ownship only).
