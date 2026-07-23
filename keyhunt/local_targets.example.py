"""Device-specific identifiers for the derivation-based searches.

Copy this file to `local_targets.py` (which is git-ignored) and fill in the real
values for YOUR device. NEVER commit `local_targets.py` — serials, MAC and the
SSID suffix are identifying and this repo is published anonymously.

- SERIALS: the two values from `GET http://192.168.4.1/?action=get` ->
  "serialNumber": "<wifi> : <adsb>".
- MAC: the AP BSSID / base MAC, hex, no separators.
- SSID: the device AP SSID (e.g. SentryPlus_ABCD).
"""

SERIALS = ["XXXXXXXXXX", "XXXXXXXXXX"]   # placeholders — replace
MAC = "AABBCCDDEEFF"                      # placeholder BSSID/base MAC
SSID = "SentryPlus_XXXX"                  # placeholder AP SSID

# Optional extra strings to try as key-derivation inputs (version/build tokens).
MISC = ["SentryPlus", "pingESP32", "uAvionix"]
