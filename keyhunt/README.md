# Traffic-key search

Scripts used to hunt the Sentry's **traffic** AES key — the second, independent
key that encrypts the `0x26` `len=20` traffic class (the ownship key
`a6b1c01f…` does **not** decrypt it). Background and full results:
[`../encrypt-mode-traffic.md`](../encrypt-mode-traffic.md).

**Status: the key is not recoverable from anything we have.** These scripts
document the exhausted search; re-run them against a *newer firmware* or the
*ForeFlight app binary* if you obtain one (see the possibilities P1–P4 in the
notes).

## Setup

```bash
pip install pycryptodome
cd keyhunt
cp local_targets.example.py local_targets.py   # fill in real serials/MAC/SSID
```

- `local_targets.py` is **git-ignored** — it holds device identifiers (serials,
  MAC, SSID) and must never be committed. Only the derivation scripts need it.
- Captures (`*.hex`, `*.pcap`) are git-ignored too — pass them as arguments.
- The **ICAO/callsign oracle** is decoded from a *public-mode* capture you pass
  with `--public`, so no observed-traffic data is ever hardcoded. A secure and a
  public capture taken close in time (same aircraft overhead) make the oracle
  valid; see the capture tools in [`../capture/`](../capture/).

## Scripts

| script | question | how |
|---|---|---|
| `keyhunt.py` | is the key a constant in a firmware image? | every 16B window as AES-ECB key vs traffic, scored by entropy (+ICAO oracle) |
| `crib_keyhunt.py` | …even if the plaintext is too dense for entropy? | exact known-plaintext cribs (ICAO + callsign ASCII + 6-bit ME) from a public capture |
| `pcap_keyhunt.py` | is the key transmitted in a ForeFlight session? | slide a key window over the raw session bytes |
| `derived_keyhunt.py` | is it a simple derivation of device IDs? | hash/pad/xor of serials/MAC/SSID (±ownship-key salt) |
| `serial_keyhunt.py` | …a thorough serial derivation? | +BCD/int/HMAC/AES(master,serial)/many salts |
| `serial_kdf_bruteforce.py` | is it `AES(firmware_master, serial)`? | that KDF over every firmware window as master |
| `mode_test.py` | is it the ownship key in a non-ECB mode (IV/stream)? | per-position entropy + pairwise-XOR structure test |

## Examples

```bash
# firmware constant (+ optional oracle):
python3 keyhunt.py Sentry_V1.0.17.bin secure_traffic.hex --public public_traffic.hex
# wider cribs:
python3 crib_keyhunt.py Sentry_V1.0.17.bin public_traffic.hex secure_traffic.hex
# key on the wire:
python3 pcap_keyhunt.py secure_traffic.hex ff_session.pcap --public public_traffic.hex
# serial derivations / KDF:
python3 serial_keyhunt.py secure_traffic.hex --public public_traffic.hex
python3 serial_kdf_bruteforce.py Sentry_V1.0.17.bin secure_traffic.hex --public public_traffic.hex
# cipher-mode diagnostic (no firmware needed):
python3 mode_test.py secure_traffic.hex
```

All of these came back **negative** against the 1.0.17 firmware, the device
identifiers, and captured ForeFlight sessions — see the notes. To reuse against
the ForeFlight app: `frida-ios-dump` the decrypted Mach-O and run
`keyhunt.py <macho> secure_traffic.hex --public public_traffic.hex` (grep the
binary for the ownship key bytes first to locate the crypto region).
