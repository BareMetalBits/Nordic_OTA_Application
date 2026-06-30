# Nordic_OTA_Application

Zephyr/NCS firmware for the nRF7002DK that auto-connects to Wi-Fi, checks a
GitHub-hosted manifest on a schedule, and OTA-updates itself via MCUboot
dual-slot swap. The running application also polls I2C sensors (currently
TMP117 + BMP280) and logs readings.

**Target:** nrf7002dk/nrf5340/cpuapp
**NCS:** v3.2.4 / Zephyr 4.2.99

---

## What it does

1. Wi-Fi auto-connect (wpa_supplicant + connection manager), wait for DHCP.
2. NTP sync (needed for TLS certificate time validation).
3. MAC-address whitelist check against a GitHub-hosted JSON list — device
   halts the OTA flow if its MAC isn't listed.
4. Fetch `update.json` (version, file path, size, SHA-256, CRC-32) over TLS.
5. Compare manifest version against the running firmware version; skip if
   already current.
6. Download the firmware binary straight into the QSPI secondary flash
   slot, computing CRC-32 incrementally. Retries from scratch (up to
   `OTA_MAX_DOWNLOAD_ATTEMPTS`) on any failure.
7. Verify CRC-32, then SHA-256 (read back from QSPI via PSA Crypto).
8. Request MCUboot test-mode swap, reboot. New image must call
   `boot_set_confirmed()` or MCUboot reverts on next boot.

This whole sequence repeats automatically: once at boot (mandatory check),
then every 24 hours via a kernel timer + semaphore-gated worker thread —
see `main.c`. Wi-Fi connection state is tracked with a persistent flag
(`wifi_net_is_connected()`), not a one-shot semaphore, so repeated polling
across cycles doesn't deadlock.

In parallel, a separate thread (`sensor_iface.c`) polls I2C sensors every
2 seconds and logs values via `LOG_INF` — no networking, console only.

## Module map

| Module | Responsibility |
|---|---|
| `main.c` | Boot init, OTA scheduling (semaphore + 24h timer + worker thread) |
| `tls_common.{c,h}` | Shared TLS socket setup, root CA registration |
| `wifi_net.{c,h}` | Wi-Fi L4 connect/disconnect handling, connection state flag |
| `ntp_sync.{c,h}` | NTP time sync, blocking with timeout |
| `mac_auth.{c,h}` | MAC whitelist fetch + check |
| `ota_manifest.{c,h}` | `update.json` fetch, parse, version compare |
| `ota_download.{c,h}` | Firmware download to QSPI, CRC-32/SHA-256 verify |
| `sensor_iface.{c,h}` | Table-driven I2C sensor polling (TMP117, BMP280, extensible) |

## Build

```
west build -b nrf7002dk/nrf5340/cpuapp .
west flash
```

Clean rebuild (use after any Kconfig/devicetree change, the merged
caches can hide stale symbols otherwise):

```
rmdir /s /q build
west build -b nrf7002dk/nrf5340/cpuapp .
```

## OTA server side

`update.json` and the firmware binary both live in the GitHub repo path
referenced by `MANIFEST_PATH`/`fw_path` in `ota_manifest.c` /
`ota_download.c` (currently `BareMetalBits/OTA_Nordic`). To publish an
update:

1. Build the new firmware image.
2. Compute its SHA-256 and CRC-32.
3. Upload the binary to the GitHub path `fw_path` points to.
4. Edit `update.json`: bump `version`, update `file_size`, `sha256`,
   `crc32`, and `fw_path` if the filename changed.
5. Devices pick it up on their next scheduled check (boot, or every 24h).

## Adding a new I2C sensor

Three steps, no changes to `sensor_poll_one()` or the thread logic:

1. **Devicetree** — add a node in the `.overlay` file on `&i2c1`, copying
   the `tmp117`/`bmp280` block as a template (node label, `compatible`
   string, I2C address).
2. **Kconfig** — enable the matching driver symbol in `prj.conf`.
3. **`sensor_iface.c`** — add a `sensor_channel_spec[]` array for the
   channels you want logged, then one entry to the `sensors[]` table
   referencing `DEVICE_DT_GET(DT_NODELABEL(your_node_label))`.

## Known gotchas (hit during development, keep an eye out)

- **Kconfig symbol names don't always match the chip name.** Zephyr
  sometimes merges multiple chip variants into one driver under a
  different symbol than you'd guess (e.g. TMP116/TMP117/TMP119 →
  `CONFIG_TMP11X`, not `CONFIG_TMP116` or `CONFIG_TMP117`). Check the
  actual `drivers/sensor/<vendor>/<part>/Kconfig` file in your NCS
  install rather than assuming.
- **`compatible = "i2c-device"` is not a real driver match** — it must be
  the exact compatible string from the driver's `.yaml` binding file, or
  no `struct device` gets generated and you'll get a linker error like
  `undefined reference to __device_dts_ord_N`.
- **`wifi_net_wait_connected()` is one-shot.** Don't call it more than
  once per connect event (e.g. from a periodic thread) — use
  `wifi_net_is_connected()` for repeated, non-blocking checks instead.
- **Stale build caches hide config fixes.** After editing `prj.conf` or
  the `.overlay`, delete `build/` before rebuilding if errors don't match
  what you just changed.
