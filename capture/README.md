# Step 1 capture tools — secure-mode traffic

Get a `0x26` (encrypted) capture **while the Sentry is hearing real ADS-B**, so
the decrypted payload contains a *traffic* message (not just ownship/AHRS).
This is the one missing capture in [`../encrypt-mode-traffic.md`](../encrypt-mode-traffic.md).

Run on a host joined to the Sentry Wi-Fi (`SentryPlus_XXXX`, open AP,
device at `192.168.4.1`).

```bash
pip install pycryptodome        # for the decrypt peek (reception probe needs it)

# 1) quick probe: connected? traffic overhead? (read-only, writes nothing)
python3 sentry_reception.py            # wants "TRAFFIC OVERHEAD"

# 2) once traffic is overhead, capture ~2 min in SECURE mode:
python3 sentry_capture.py 120 secure_traffic.hex
#    forces publicGDL90=false, saves each datagram as "<epoch> <hex>",
#    warns if any non-0x25/0x26 id appears, flags inner 0x21/DF17 hits live.
#    --no-set leaves the mode untouched; --device 192.168.4.1 to override.
```

Both tools send the **ForeFlight discovery announce** to `:63093` themselves —
the Sentry only unicasts GDL90 to a client that has announced, so a fresh client
IP gets nothing until it does. (The announce selects the GDL90 port, *not* the
encryption mode.) No manual step needed.

Success = the capture summary prints **`TRAFFIC FOUND`** (an inner
`21 ff ff ff 8D…` DF17). Keep that `.hex` — it feeds step 2 (offline
decrypt/identify). If it says no traffic, the Sentry heard nothing; reposition
to sky-view (the reception probe should say `TRAFFIC OVERHEAD`) and recapture.
The traffic detector is deliberately strict, so a `TRAFFIC FOUND` is almost
certainly real; if aircraft are definitely overhead per an independent SDR but
nothing is flagged, capture anyway and let step 2 analyze it (traffic may use a
non-`0x21` inner format — that is exactly what step 2 resolves).

**Leaves the device secure** (that is the point — passive decryption of an
unmodified Sentry). No revert needed.

## Network setup used here (Pi with two radios)

Management stays on wired `eth0`; the Sentry gets its own radio:

- `eth0` — home LAN (SSH/management).
- `wlan1` (USB ath9k_htc / AR9271) — joined to the Sentry AP. This adapter
  **associates but its DHCP never completes**, so it uses a **static IP**
  instead: NM profile `sentry-wlan1`, `ipv4.method manual`,
  `ipv4.addresses 192.168.4.123/24`, `ipv4.never-default yes` (so it does not
  hijack the default route). Bring up with `nmcli con up sentry-wlan1`.
- `wlan0` — free for the home network.

(If you use the built-in radio instead, DHCP works normally — just
`nmcli dev wifi connect "SentryPlus_XXXX"`.)
