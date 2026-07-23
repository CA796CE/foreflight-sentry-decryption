# Finding traffic in encrypt (`0x26`) mode

**Goal:** with the device left *secure* (`publicGDL90=false`), recover **traffic**
(other aircraft) from the encrypted `0x26` stream using the AES key
`a6b1c01f2200566268937c708a06ddcf` (AES-128-ECB, null IV).

## Status (2026-07-22): captured secure+traffic — **traffic is NOT decryptable with our key**

**The one missing capture was taken (outdoors, 8 aircraft overhead, confirmed by
a public-mode ground-truth toggle), and the result overturns the hypothesis
below.** See "Findings 2026-07-22". In short:

- **Encrypted traffic is NOT an inner `0x21` under our key.** It is a distinct
  `0x26` **length class (`len=20`, `26 00` + 18 B)** that runs at ~16.7/s —
  matching the ~19/s of plaintext `0x21` traffic for the same 8 aircraft, and
  which **disappears entirely in public mode** (where traffic becomes `0x21`).
- **Our key `a6b1c01f…` does NOT decrypt that class.** Decrypting it leaves full
  entropy (7.94 bits, unchanged), and none of the 8 known-overhead ICAOs appear
  in the raw *or* decrypted bytes (either byte order). Ownship/AHRS/GPS
  (`0x27`/`0x28`) still decrypt cleanly with the same key.
- **Conclusion: the Sentry uses two crypto contexts.** The extracted key unlocks
  **ownship** only; **traffic is under a second, unknown key** (per-device or a
  separate global key). This is why every prior secure capture showed only
  ownship — not because it heard no traffic, but because traffic was invisible to
  our key even when present.

**Practical upshot:** passive traffic decryption is **blocked pending the traffic
key**. The working path for traffic today is **`publicGDL90` mode** (plaintext
`0x21` → the `transcoder/` already turns it into standard `0x14`). To passively
decrypt traffic on an unmodified Sentry we now need to recover the *second* key
(see "Getting the traffic key" below).

Artifacts: `~/tmp/sentry/secure_traffic_154957.hex`, `secure_hunt.hex` (secure +
traffic), `public_gt.hex` (public-mode ground truth, 8 ICAOs), and
`analyze*.py` / `hunt.py` / `pubcheck.py`.

---

## (superseded) Status: method ready, traffic not yet captured in encrypt mode

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

## Findings 2026-07-22 (the capture that settled it)

Setup: capture host `pisentry`, wlan1 (ath9k_htc) static `192.168.4.123` on the
Sentry AP, eth0 for management. Tools in `capture/` (`sentry_capture.py`,
`sentry_reception.py`). Two gotchas found and fixed: (1) the Sentry only unicasts
:4000 to a client that has sent the discovery announce to `:63093` — the tools
now send it; (2) our first live detector over-decrypted the trailer and threw
false `0x21` hits — tightened to the exact `21 ff ff ff 8D…` signature.

**0x26 length classes in a 30 s secure capture with 8 aircraft overhead:**

| len | count | rate | decrypt (our key) |
|---|---|---|---|
| 20 | 500 | 16.7/s | **fails** — entropy 7.94 unchanged; first byte random; = **traffic** |
| 68 | 139 | 4.6/s | `0x28` AHRS (48 B ct + 18 B plaintext trailer) ✔ |
| 18 | 54 | 1.8/s | `0x28` (subtype 01) ✔ |
| 45 | 28 | 0.9/s | `0x27` GPS ✔ |
| 41 | 5 | — | `0x28` (subtype 06) ✔ |

**Ground truth (public-mode toggle, `pubcheck.py`):** flipping `publicGDL90=true`
for 15 s decoded **285 `0x21` DF17 frames, 8 distinct ICAOs** (`XXXXXX XXXXXX
XXXXXX XXXXXX XXXXXX XXXXXX XXXXXX XXXXXX`), then reverted cleanly. In public
mode there is **no `0x26` at all**. So the secure `len=20` class (~16.7/s) is the
same traffic that public mode emits as `0x21` (~19/s).

**Hunt for those 8 ICAOs in a same-moment secure capture (`hunt.py`):** absent
from the **raw ciphertext** and from the **decrypted** bytes, in **both** byte
orders. Combined with the unchanged 7.94-bit entropy after decryption, this means
our key is simply **wrong for the traffic class** — not a format/offset problem.

→ **Two keys.** `a6b1c01f…` = ownship key (AHRS/GPS/status). Traffic has its own
key we do not have.

## Getting the traffic key — brute force EXHAUSTED (2026-07-22)

Confirmed first: **`len=20` traffic is AES-128-ECB**. 316 distinct blocks in
`secure_hunt.hex` but with heavy repeats (one block ×27) — far more collisions
than random, i.e. identical plaintext → identical ciphertext. The repeats occur
at content offset **2**, which **pins the ECB block boundary at offset 2**
(`26 00` + 16 B ciphertext + 2 B trailer). So brute forcing at offset 2 is
correctly aligned; CBC/CTR/random-IV are ruled out.

Both static attacks ran and came back **negative** (`keyhunt.py`,
`derived_keyhunt.py`):

1. **Static firmware constant — NO.** Tried all **945,959** 16-byte windows of
   `Sentry_V1.0.17.bin` as AES-128-ECB keys (offsets 2 and 4), scored by
   decrypted entropy + known-ICAO search. Entropy floor **7.85** (the ownship key
   dipped to **6.96**); zero ICAO hits. The traffic key is **not a raw constant
   in the 1.0.17 image**.
2. **Derived from device identifiers — NO.** 125 candidates from serials, MAC,
   SSID, versions via pad/MD5/SHA1/SHA256/xor(±ownship-key salt). Best entropy
   **7.90** (worse than random); no real ICAO hit (the ownship key scores 7.908
   on traffic, confirming the oracle rejects wrong keys). **Not a simple
   derivation of the identifiers we have.**
3. **Wider known-plaintext cribs — NO** (`crib_keyhunt.py`). Decoded the
   public-mode `0x21` traffic to get each aircraft's **callsign** (the observed
   targets were airliners, so DF17 identity carried flight-ID callsigns, not
   N-numbers) and built exact cribs: ICAO (both endian), callsign ASCII (raw +
   8-pad), and the raw 6-bit-packed identity bytes. Searched every firmware
   window's decrypt of all 316 `len=20` blocks. **Zero long-crib (≥4 B) hits;**
   the 3-byte ICAO "hits" matched the count expected purely by chance (~4.5k),
   i.e. noise. So even with a time-invariant callsign crib, no 1.0.17 window is
   the key. (This also matters because a dense traffic plaintext can defeat the
   entropy test — the crib test does not depend on entropy, and still finds
   nothing.)

**Note on static decompilation:** reading the key straight out of decompiled code
is not available — Ghidra's Xtensa decompiler `halt_baddata`s on exactly the
crypto/key-setup functions (see `firmware-crypto-notes.md`), which is why even the
ownship key was brute-forced, not read. And since brute force tests *every*
16-byte window, an unreadable-but-present constant would still have been found.
The `publicGDL90` global (`0x3ffb6c5c`) is read only in config/setter/log paths
(`0x400e431b`, `0x400e514c`, `0x400f4015`), not an inline per-message encrypt
branch — the encrypt decision is wired in indirectly, so there is no simple
"trace the branch to the key" shortcut.

So the traffic key is one of: **(a) a static constant that exists only in the
deployed 1.0.32 image** (not in the 1.0.17 dump we have — the ownship key was
version-stable but the traffic key need not be), **(b) a non-obvious KDF / a
secret not in our identifier set**, or **(c) computed at runtime only**.

### Viable remaining paths (need more than we currently have)
1. **Obtain the 1.0.32 firmware and re-run `keyhunt.py`.** Cheapest if it's a
   version-specific constant. Getting it is the hard part: the device exposes no
   flash-read over HTTP (`/espUpdate` only *writes*); options are sniffing a real
   OTA to the device, an online 1.0.32 dump, or a flash read over UART/JTAG
   (case entry; USB-C is charge-only).
2. **RAM dump — definitive.** The key sits in the mbedtls AES context in RAM
   regardless of how it's derived. Via `/coredump` (needs inducing a panic; the
   endpoint is currently empty) or JTAG/UART (secure-boot/flash-encryption are
   OFF, so unobstructed once the case is open). Same fallback noted for the
   ownship key in `firmware-crypto-notes.md`.
3. **Frida on ForeFlight (iOS).** Dumps the runtime key *and* the decrypted
   traffic format; needs a jailbroken/instrumentable device.

Until one of those lands, **traffic on an unmodified (secure) Sentry is not
recoverable** — use `publicGDL90` mode for traffic (`0x21` → `transcoder/`).

Scripts: `~/tmp/sentry/keyhunt.py` (static), `derived_keyhunt.py` (derived).

## Open items
- Recover the **traffic key** (above) — the real remaining blocker for passive
  traffic decode.
- Decode the `0x28` (AHRS) / `0x27` (GPS) ownship fields (separate effort; see the
  controlled-stimulus plan) — bonus attitude + GPS source.
- Confirm the exact `len=20` layout (header bytes 2–3 vary; 16 B block + 2 B
  counter/CRC?) once the key is known.

## Artifacts
- Key + brute-force method: `firmware-crypto-notes.md`
- Public-mode transcoder (the `0x21`→`0x14` half): `transcoder/`
- Captures: `~/tmp/sec_traffic*.hex` (indoor, no traffic), `~/tmp/datagrams.hex`
  (indoor secure, ownship only).
