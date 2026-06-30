#define OTA_DOWNLOAD_H

#include <stddef.h>
#include <stdint.h>

/*
 * ota_download.h — Firmware download to QSPI secondary slot, CRC-32 and
 * SHA-256 verification.
 *
 * Extracted from main.c: open_secondary_slot(), download_firmware(),
 * verify_crc32(), verify_sha256(), find_body_start(), and the associated
 * static buffers (g_fw_stream, g_stream_buf, g_fw_fa, fw_recv_buf).
 * All logic identical to the original.
 *
 * download_firmware() and verify_crc32()/verify_sha256() now take a
 * `const struct ota_manifest *manifest` parameter instead of reading the
 * file-static g_manifest directly — this is the one intentional design
 * change recommended during the modularisation discussion (explicit
 * dependency instead of implicit global), not a behavioural change: the
 * exact same fields (fw_path, file_size, sha256, crc32) are read in the
 * exact same way.
 */

struct ota_manifest; /* forward declaration — full definition in ota_manifest.h */

/**
 * @brief Download the firmware binary named in manifest->fw_path to the
 * QSPI secondary slot, computing CRC-32 incrementally as data arrives.
 *
 * Each call starts completely fresh: re-opens the secondary slot, re-inits
 * stream_flash, and re-downloads from byte 0 — identical behaviour to the
 * original, safe to call repeatedly from a retry loop.
 *
 * @param manifest   Parsed manifest (must have fw_path set).
 * @param out_crc    Receives the CRC-32 of all bytes written.
 * @param out_bytes  Receives the total byte count written.
 * @return 0 on success, negative errno on failure.
 */
int ota_download_firmware(const struct ota_manifest *manifest,
                          uint32_t *out_crc, size_t *out_bytes);

/**
 * @brief Verify the CRC-32 computed during download against the manifest.
 *
 * Identical to the original verify_crc32(): also checks received_bytes
 * against manifest->file_size before comparing the CRC value.
 *
 * @return 0 on match, -EMSGSIZE on size mismatch, -EBADMSG on CRC mismatch.
 */
int ota_download_verify_crc32(const struct ota_manifest *manifest,
                              uint32_t computed, size_t received_bytes);

/**
 * @brief Verify SHA-256 by reading back the firmware from QSPI flash.
 *
 * Identical to the original verify_sha256(): PSA Crypto read-back in
 * 512-byte chunks, hex-compared against manifest->sha256.
 *
 * @return 0 on match, -EBADMSG on hash mismatch, other negative errno on
 *         flash/PSA error.
 */
int ota_download_verify_sha256(const struct ota_manifest *manifest);
