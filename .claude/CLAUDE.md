# Anonymity — read before committing

**This repo is published anonymously (GitHub user CA796CE). Do NOT add
anything that could identify the author, their hardware, or their location.**

Never commit:
- **Real names / handles** — including in device names, hostnames, paths,
  or example strings.
- **MAC / BSSID addresses** — use `AA:BB:CC:DD:EE:FF`.
- **SSIDs that embed a device MAC or serial** (e.g. `SentryPlus_<hex>`) —
  redact the suffix to `XXXX`.
- **Aircraft tail numbers / N-numbers** (ours or a linked panel, e.g. a
  SkyView station SSID) — redact to `XXXXX`.
- **Serial numbers** (device, ADS-B module) — redact to `XXXXXXXX`.
- **Local hostnames** of our own capture/sniffer machines — use a generic
  name like `sniffer-host`.
- **App / OS build fingerprints** (ForeFlight build, CFNetwork/Darwin
  version, iOS version) that tie captures to our specific device.
- **Observed live ADS-B callsigns / tail numbers** — they leak our location
  and time. Use generic placeholders ("several targets").
- **Device-specific calibration** (AHRS offsets, etc.).

When in doubt, redact with an obvious placeholder (`XXXX`, `<redacted>`).
Before any commit, grep the diff for the patterns above.

Identity/config for this repo is pinned in `.git/config`
(`user.name = CA796CE`, signing disabled, anonymous SSH key via
`core.sshCommand`). Do not commit with a personal identity, and do not sign
commits.
