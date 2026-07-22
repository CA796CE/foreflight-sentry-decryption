# Firmware crypto path — key hunt (SOLVED)

RE of the plaintext OTA image (`Sentry_V1.0.17.bin`, classic ESP32 / Xtensa LX6)
using an ELF rebuilt from the segments + radare2. Goal: extract the AES key that
encrypts the `0x26` GDL90 payload.

> Status: **SOLVED — key extracted.**
> ```
> AES-128-ECB, null IV
> key = a6b1c01f2200566268937c708a06ddcf   (firmware 1.0.17 @ offset 0xc40a)
> ```
> Found by brute force (below), verified against the live 1.0.32 device — the key
> is stable across firmware versions and matches cbpowell's report (16-byte
> hardcoded, AES-128-ECB, null IV). This enables **passive decryption of an
> unmodified Sentry** (no need to flip `publicGDL90`).

## How the key was found (brute force, given cbpowell's AES-128-ECB hint)
The 16-byte key is a hardcoded constant *somewhere* in the plaintext firmware
image, and ECB decrypts each block independently — so every 16-byte window of the
firmware is a candidate key, testable against a captured `0x26` ciphertext block:

1. Collect `0x26` payloads from a secure-mode capture; the encrypted region starts
   at **offset 2** (after `26 00`), in 16-byte blocks; the last 18 bytes are a
   plaintext trailer.
2. For each of the ~946k 16-byte firmware windows, AES-128-ECB-decrypt ~30 frames'
   first block and score by **entropy of the decrypted bytes** (format-agnostic:
   the right key turns random-looking ciphertext into low-entropy structure).
3. Winner stood out sharply: **6.96 bits** vs 7.51 for the next candidate.
4. Verified: whole-stream decrypt entropy 7.93 → 6.39; decrypted first-byte
   histogram dominated by uAvionix IDs (`0x28`×591, `0x27`, `0x25`); and decrypted
   frames match the **public-mode `0x28`/`0x27` messages field-for-field**
   (e.g. `2806 01.. ....8957e0..`). Script: `../transcoder/` + `Crypto.Cipher.AES`.

## Decrypt recipe
```python
from Crypto.Cipher import AES
KEY = bytes.fromhex('a6b1c01f2200566268937c708a06ddcf')
def decrypt_0x26(content):           # content = destuffed, CRC-stripped, starts 26 00
    nblk = (len(content) - 2) // 16  # last ~18B is a plaintext trailer, not encrypted
    pt = AES.new(KEY, AES.MODE_ECB).decrypt(content[2:2+16*nblk])
    return pt                        # uAvionix message(s): 0x28/0x27/0x25/...
```

## (original static-RE notes below — superseded by the brute-force result)


## Confirmed: it's standard ESP32 **hardware AES**
The ESP32 AES accelerator registers are driven from `0x4010fc25`–`0x4010fc41`:
- `0x3ff01008` = `AES_KEY_0` (key loaded here)
- `0x3ff01000` = `AES_MODE`, `0x3ff01004` = endian, `0x3ff01010` = text
This matches the traffic-analysis evidence (16-byte blocks, ECB-mode leakage).
So the cipher is genuine AES — the only unknown is the key.

## Encrypt call chain (top → hardware)
```
GDL90 output builder
  └─ call 0x400db7e0   "encrypt+stuff one GDL90 frame"
        • entry a1,0x260; zeroes a work buffer
        • writes 0x26 (msg id) to buf[0]           <- builds the 0x26 frame
        └─ call 0x400ed9a0(data,len)
        └─ call 0x400ed8c4(buf)                     <- crypto wrapper
              └─ call 0x400de3a4 / 0x400de3dc
                    └─ call 0x40124000 / 0x4012426c / 0x40123f94 / 0x4012436c
                          (mbedtls AES region 0x40124xxx)
                          └─ HW AES driver @ 0x4010fc00  (writes key -> 0x3ff01008)
  on failure -> ESP_LOGW "Failed to encrypt/stuff GDL90 message" @ 0x400d87d6
```

The caller that logs the failure is at `0x400d87c0`–`0x400d87e1` (calls
`0x400db7e0`, branches on its return, logs on zero).

## Why the key didn't fall out of static RE (yet)
- The key is passed **by pointer** through the windowed-ABI call chain (a4/a5/a10…
  rotate across `call8`/`call12`), so it isn't a single obvious `l32r` in the
  encrypt function. Tracking it needs **data-flow analysis** (a decompiler), which
  radare2's Xtensa support doesn't do well; manual tracing desyncs in the deeper
  layers.
- Two possibilities remain open:
  1. **Hardcoded global key** — a 16/32-byte constant in `.rodata`/`.data`,
     memcpy'd into the mbedtls context during a one-time init we haven't located.
  2. **Derived key** — e.g. from the device serial (`XXXXXXXXXX`/`XXXXXXXXXX`) or
     another secret; then there is no static constant and it must be recovered at
     runtime.

## Best next steps to actually get the key
1. **Ghidra + Xtensa processor module** on the rebuilt ELF: decompile `0x400db7e0`
   → follow the buffer/ctx into `0x400ed8c4`/`0x40124xxx`, read the key pointer /
   the `mbedtls_aes_setkey_enc(ctx, KEY, bits)` call. Highest-confidence path.
2. **Runtime RAM dump** (key is in the mbedtls context in RAM regardless of how it
   was set):
   - the web UI exposes **`/coredump`** (served when `coredump==true`) — a crash
     dump would contain the AES context; or
   - JTAG/UART if the case is opened (flash encryption + secure boot are OFF, so a
     RAM/flash dump is unobstructed).
3. If the global-key hypothesis holds, one extraction unlocks **all** Sentries and
   lets any tool passively decrypt the `0x26` stream without touching the device.

## Ghidra decompile attempt (2026-07-20) — blocked by Xtensa decompiler gaps

Ghidra **12.1.2 ships a built-in Xtensa processor** (`Xtensa:LE:32:default`). It
imported the rebuilt ELF and decompiled most of the firmware. Key results:

- **`FUN_400db7e0` decompiled cleanly** — confirms the frame builder:
  ```c
  memset(buf, 0, 0x232);
  buf[0] = 0x26;                       // GDL90 msg id
  if (FUN_400ed9a0(data, len-2, ...) == 0) {   // builds ownship/AHRS payload (float math)
      FUN_400ed8c4(buf);               // <-- encrypts buf in place
      out = FUN_400db768(param1, buf, n);       // byte-stuff + emit
  }
  ```
- **The key-bearing functions do NOT decompile** — Ghidra's Xtensa module can't
  model some opcodes in them ("Unable to resolve constructor" → `halt_baddata`):
  `FUN_400ed8c4` (encryptor), `FUN_400de3dc` (crypto wrapper), `FUN_4012426c`
  (setkey), `FUN_4010fbe0`/`FUN_4010fc00` (HW-AES key loader).
- The functions that DID decompile in the AES region are just the peripheral
  plumbing (DMA wait loops, `memw()` barriers, writes to AES regs `+0x28/+0x2c/
  +0x44`) — no key material.
- The AES **key is set once at init** into a context in RAM, not in the per-frame
  path; that init wasn't located, and the decompiler gaps block reading it.

### Bottom line on static extraction
Blocked by two things at once: (1) Ghidra's Xtensa decompiler opcode gaps land
exactly on the crypto/key functions, and (2) the key setup is a one-time init
that isn't in the traced per-frame path. Fully mapped, cipher confirmed as ESP32
HW-AES, but the **key bytes remain unrecovered by static RE with current tools.**

### Best remaining path: RAM dump
The key lives in the mbedtls AES context (and AES peripheral) in RAM, independent
of the decompiler gaps:
- **Induce a coredump** (the `/coredump` endpoint is configured but currently
  empty/size 0 — needs a panic) then `/coredump?action=download` and carve the
  key from the RAM image. Downside: inducing a crash is invasive/uncertain.
- **JTAG** (GPIO12–15) or UART `esptool` RAM read — needs opening the case
  (USB-C is charge-only). Secure-boot/flash-encryption are OFF, so unobstructed.

## Artifacts
- `~/tmp/sentry-fw/firmware.elf` (rebuilt ELF for Ghidra/r2)
- `~/tmp/sentry-fw/Sentry_V1.0.17.bin` (original OTA image)
- `~/tmp/sentry-fw/seg2.disasm.txt` (full objdump), `l32r_sites.txt`, etc.
