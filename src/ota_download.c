/*
 * ota_download.c — Firmware download, CRC-32, and SHA-256 verification.
 *
 * download_firmware(), verify_crc32(), verify_sha256(), open_secondary_slot(),
 * and find_body_start() bodies are byte-for-byte identical to the originals
 * in main.c. The only change is reading manifest fields through a passed-in
 * `const struct ota_manifest *manifest` parameter instead of the file-static
 * g_manifest global — same field names, same values, same access pattern,
 * just passed explicitly across the module boundary instead of shared
 * implicitly within one file.
 */

#include "ota_download.h"
#include "ota_manifest.h"
#include "tls_common.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/sys/crc.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/storage/stream_flash.h>

#include <psa/crypto.h>

LOG_MODULE_REGISTER(ota_download, LOG_LEVEL_INF);

/* ── GitHub endpoint ──────────────────────────────────────────────────────── */
#define GITHUB_HOST    "raw.githubusercontent.com"
#define GITHUB_PORT    "443"

/*
 * Firmware download recv buffer: 4 KB matches the MX25R6435F sector.
 * Stored in BSS (no flash cost, only RAM). With 512 KB RAM this is fine.
 */
#define FW_RECV_BUF_SIZE       4096
/* stream_flash internal buffer: must equal or be a multiple of the erase unit. */
#define STREAM_FLASH_BUF_SIZE  4096

/* ── Flash context (global — too large for stack) ────────────────────────── */
static struct stream_flash_ctx g_fw_stream;
static uint8_t                 g_stream_buf[STREAM_FLASH_BUF_SIZE];
static const struct flash_area *g_fw_fa;

/* ── Firmware download recv buffer ───────────────────────────────────────── */
static uint8_t fw_recv_buf[FW_RECV_BUF_SIZE];

static const uint8_t *find_body_start(const uint8_t *buf, size_t len)
{
    for (size_t i = 0; (i + 3) < len; i++) {
        if (buf[i]   == '\r' && buf[i+1] == '\n' &&
            buf[i+2] == '\r' && buf[i+3] == '\n') {
            return buf + i + 4;
        }
    }
    return NULL;
}

static int open_secondary_slot(void)
{
    int ret = flash_area_open(FIXED_PARTITION_ID(mcuboot_secondary), &g_fw_fa);
    if (ret != 0) {
        LOG_ERR("flash_area_open(mcuboot_secondary) failed: %d. "
                "Verify PM_MCUBOOT_SECONDARY_ID in pm_config.h", ret);
        return ret;
    }

    const struct device *flash_dev = flash_area_get_device(g_fw_fa);
    if (!device_is_ready(flash_dev)) {
        LOG_ERR("QSPI flash device not ready. "
                "Check CONFIG_NORDIC_QSPI_NOR=y and board DTS node.");
        flash_area_close(g_fw_fa);
        return -ENODEV;
    }

    ret = stream_flash_init(&g_fw_stream,
                            flash_dev,
                            g_stream_buf,
                            sizeof(g_stream_buf),
                            g_fw_fa->fa_off,
                            g_fw_fa->fa_size,
                            NULL);
    if (ret != 0) {
        LOG_ERR("stream_flash_init failed: %d", ret);
        flash_area_close(g_fw_fa);
    }
    return ret;
}

/*
 * Each call starts completely fresh: re-opens the secondary slot, re-inits
 * stream_flash, and re-downloads from byte 0. CONFIG_STREAM_FLASH_ERASE=y
 * re-erases each 4 KB sector before writing, so calling this repeatedly
 * from main()'s retry loop after a failed/interrupted attempt is safe.
 */
int ota_download_firmware(const struct ota_manifest *manifest,
                          uint32_t *out_crc, size_t *out_bytes)
{
    int ret = open_secondary_slot();
    if (ret != 0) {
        return ret;
    }

    int sock = tls_common_open_socket(GITHUB_HOST, GITHUB_PORT);
    if (sock < 0) {
        flash_area_close(g_fw_fa);
        return sock;
    }

    char req[384];
    int  req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.0\r\n"
        "Host: %s\r\n"
        "\r\n",
        manifest->fw_path, GITHUB_HOST);

    if (send(sock, req, req_len, 0) < 0) {
        LOG_ERR("firmware GET send() failed, errno %d", errno);
        close(sock);
        flash_area_close(g_fw_fa);
        return -errno;
    }

    LOG_INF("Downloading firmware from %s ...", manifest->fw_path);

    uint32_t running_crc    = 0;
    size_t   bytes_written  = 0;
    bool     headers_skipped = false;
    int      n;

    while (true) {
        n = recv(sock, fw_recv_buf, sizeof(fw_recv_buf), 0);
        if (n < 0) {
            LOG_ERR("firmware recv() failed, errno %d", errno);
            ret = -errno;
            goto cleanup;
        }
        if (n == 0) {
            break;
        }

        const uint8_t *data     = fw_recv_buf;
        size_t         data_len = (size_t)n;

        if (!headers_skipped) {
            const uint8_t *body = find_body_start(fw_recv_buf, data_len);
            if (!body) {
                continue;
            }
            headers_skipped = true;
            data_len = data_len - (size_t)(body - fw_recv_buf);
            data     = body;
            LOG_INF("HTTP headers consumed. Firmware data starting.");
        }

        if (data_len == 0) {
            continue;
        }

        ret = stream_flash_buffered_write(&g_fw_stream, data, data_len, false);
        if (ret != 0) {
            LOG_ERR("stream_flash write failed at offset %zu: %d",
                    bytes_written, ret);
            goto cleanup;
        }

        running_crc   = crc32_ieee_update(running_crc, data, data_len);
        bytes_written += data_len;
    }

    ret = stream_flash_buffered_write(&g_fw_stream, NULL, 0, true);
    if (ret != 0) {
        LOG_ERR("stream_flash flush failed: %d", ret);
        goto cleanup;
    }

    LOG_INF("Download complete: %zu bytes written to QSPI secondary slot",
            bytes_written);
    *out_crc   = running_crc;
    *out_bytes = bytes_written;
    ret = 0;

cleanup:
    close(sock);
    flash_area_close(g_fw_fa);
    return ret;
}

int ota_download_verify_crc32(const struct ota_manifest *manifest,
                              uint32_t computed, size_t received_bytes)
{
    if ((int)received_bytes != manifest->file_size) {
        LOG_ERR("File size mismatch: received %zu bytes, manifest says %d",
                received_bytes, manifest->file_size);
        return -EMSGSIZE;
    }

    uint32_t expected = (uint32_t)strtoul(manifest->crc32, NULL, 16);
    if (computed != expected) {
        LOG_ERR("CRC32 FAIL — computed 0x%08X, expected 0x%08X",
                computed, expected);
        return -EBADMSG;
    }

    LOG_INF("CRC32 OK: 0x%08X", computed);
    return 0;
}

int ota_download_verify_sha256(const struct ota_manifest *manifest)
{
    int ret = flash_area_open(FIXED_PARTITION_ID(mcuboot_secondary), &g_fw_fa);
    if (ret != 0) {
        LOG_ERR("Cannot open secondary slot for SHA-256 read-back: %d", ret);
        return ret;
    }

    psa_hash_operation_t op  = PSA_HASH_OPERATION_INIT;
    psa_status_t         psa = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (psa != PSA_SUCCESS) {
        LOG_ERR("psa_hash_setup failed: %d", psa);
        flash_area_close(g_fw_fa);
        return -EIO;
    }

    uint8_t read_buf[512];
    size_t  remaining = (size_t)manifest->file_size;
    size_t  offset    = 0;

    while (remaining > 0) {
        size_t to_read = MIN(remaining, sizeof(read_buf));

        ret = flash_area_read(g_fw_fa, offset, read_buf, to_read);
        if (ret != 0) {
            LOG_ERR("flash_area_read at offset %zu failed: %d", offset, ret);
            psa_hash_abort(&op);
            flash_area_close(g_fw_fa);
            return ret;
        }

        psa_hash_update(&op, read_buf, to_read);
        offset    += to_read;
        remaining -= to_read;
    }

    flash_area_close(g_fw_fa);

    uint8_t hash[32];
    size_t  hash_len;

    psa = psa_hash_finish(&op, hash, sizeof(hash), &hash_len);
    if (psa != PSA_SUCCESS) {
        LOG_ERR("psa_hash_finish failed: %d", psa);
        return -EIO;
    }

    char hash_str[65];
    for (int i = 0; i < 32; i++) {
        snprintf(&hash_str[i * 2], 3, "%02x", hash[i]);
    }
    hash_str[64] = '\0';

    if (strcmp(hash_str, manifest->sha256) != 0) {
        LOG_ERR("SHA-256 FAIL");
        LOG_ERR("  computed : %s", hash_str);
        LOG_ERR("  expected : %s", manifest->sha256);
        return -EBADMSG;
    }

    LOG_INF("SHA-256 OK: %s", hash_str);
    return 0;
}