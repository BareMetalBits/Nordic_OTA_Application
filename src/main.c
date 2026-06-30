/*
 * OTA Firmware Update Client — Stage 8 (Periodic, semaphore + thread)
 * Target : nrf7002dk/nrf5340/cpuapp     NCS : v3.2.4
 *
 * Full pipeline (unchanged from the previous modularised version):
 *  1. Wi-Fi auto-connect (wpa_supplicant + connection manager)
 *  2. 5 s routing stabilisation
 *  3. NTP time sync  (required for TLS cert notBefore/notAfter check)
 *  4. MAC address authentication against GitHub whitelist
 *  5. HTTPS fetch of update.json  → parse 5 fields only
 *  6. Semver version check         → skip if already current
 *  7. HTTPS download of firmware binary → stream directly to QSPI secondary slot
 *     (auto-restarts from scratch, up to OTA_MAX_DOWNLOAD_ATTEMPTS times, on
 *      any download or integrity failure)
 *  8. CRC-32 verification          → computed during download, zero extra RAM
 *  9. SHA-256 verification         → read-back from QSPI flash via PSA Crypto
 * 10. boot_request_upgrade()       → test-mode swap request
 * 11. sys_reboot()                 → MCUboot swaps primary ↔ secondary on next boot
 *     New firmware must call boot_set_confirmed() or MCUboot reverts on timeout.
 *
 * NEW in Stage 8 — periodic execution:
 *   The pipeline above (steps 1-11, minus the one-time Wi-Fi/TLS/LED init
 *   which now happens once in main()) runs inside a dedicated OTA thread,
 *   gated by a semaphore (sem_ota_trigger):
 *     - sem_ota_trigger starts at count 1, so the OTA pipeline still runs
 *       immediately on boot — identical first-run behaviour to before.
 *     - A k_timer (ota_timer) is started with period OTA_INTERVAL,
 *       and on every expiry calls k_sem_give(&sem_ota_trigger) from timer
 *       (ISR) context, waking the OTA thread for the next cycle.
 *     - If the pipeline succeeds, boot_request_upgrade()+sys_reboot() fires
 *       as before and the device restarts (timer/semaphore re-init on boot).
 *     - If the pipeline fails or finds no update, the OTA thread simply
 *       loops back to k_sem_take() and sleeps until the *next* full 24 h
 *       timer expiry — no shortened retry interval after a failed cycle.
 *
 * Module map:
 *   tls_common.{c,h}    — shared TLS socket setup + root CA registration
 *   wifi_net.{c,h}      — Wi-Fi L4 connect/disconnect event handling
 *   ntp_sync.{c,h}      — NTP time sync
 *   mac_auth.{c,h}      — MAC whitelist authentication
 *   ota_manifest.{c,h}  — update.json fetch + parsing + version compare
 *   ota_download.{c,h}  — firmware download, CRC-32, SHA-256 verification
 *   sensor_iface.{c,h}  — I2C sensor polling thread (TMP117 + BMP280,
 *                         table-driven — see sensor_iface.c to add more)
 */

#include <errno.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/dfu/mcuboot.h>

#include "tls_common.h"
#include "wifi_net.h"
#include "ntp_sync.h"
#include "mac_auth.h"
#include "ota_manifest.h"
#include "ota_download.h"
#include "sensor_iface.h"

LOG_MODULE_REGISTER(OTA_Client, LOG_LEVEL_INF);

/* ── Version ──────────────────────────────────────────────────────────────── */
#define FIRMWARE_VERSION_CURRENT  "1.1.2"

/* ── Download retry policy ───────────────────────────────────────────────── */
/* On any download or integrity-check failure, restart the firmware download
 * from byte 0 (up to this many total attempts) rather than giving up. */
#define OTA_MAX_DOWNLOAD_ATTEMPTS   3
#define OTA_RETRY_DELAY_MS          3000

/* ── Periodic OTA scheduling ─────────────────────────────────────────────── */
/* How often the whole OTA pipeline is re-run. On a failed/no-update cycle
 * the thread waits this full duration again before the next attempt.
 *
 * *** TESTING VALUE *** — set to 2 minutes so you don't have to wait 24 h
 * to see repeat cycles. Change back to K_HOURS(24) before production. */
#define OTA_INTERVAL  K_MINUTES(2)

#define OTA_THREAD_STACK_SIZE  4096
#define OTA_THREAD_PRIORITY    7

/*
 * sem_ota_trigger — gates the OTA worker thread.
 * Initial count 1 so the pipeline runs once immediately at boot (matching
 * the previous behaviour). Every subsequent k_sem_give() comes from
 * ota_timer_handler() on each 24 h timer expiry.
 */
static K_SEM_DEFINE(sem_ota_trigger, 1, 1);

static void ota_timer_handler(struct k_timer *timer_id)
{
    ARG_UNUSED(timer_id);
    LOG_INF("24 h OTA timer expired — triggering scheduled OTA check.");
    k_sem_give(&sem_ota_trigger);
}

K_TIMER_DEFINE(ota_timer, ota_timer_handler, NULL);

/* ═══════════════════════════════════════════════════════════════════════════
 * ota_run_once() — single end-to-end OTA pipeline pass.
 *
 * Identical logic to the previous main(): MAC auth → manifest fetch →
 * version check → download/verify retry loop → MCUboot upgrade request →
 * reboot. On success this function never returns (sys_reboot()). On any
 * failure or "already up to date" outcome it returns a status code so the
 * caller can simply log it and wait for the next cycle.
 *
 * Wi-Fi connect/DHCP and NTP sync are repeated on every cycle (not just at
 * boot) since the connection may have dropped between runs — same effect
 * as the original blocking calls, just re-entered each pass.
 * ═══════════════════════════════════════════════════════════════════════════ */
static int ota_run_once(void)
{
    int ret;

    /* ── 1. Ensure Wi-Fi + DHCP are up ───────────────────────────────────── */
    /*
     * NOTE: do NOT call wifi_net_wait_connected() here — that semaphore is
     * one-shot per connect event and is already consumed once at boot in
     * main(). If the link stays connected (the normal case), the event
     * never refires, so calling it again here would block this thread
     * forever on the 2nd+ cycle. Poll the persistent flag instead.
     */
    while (!wifi_net_is_connected()) {
        LOG_WRN("Wi-Fi not connected — waiting before this OTA cycle...");
        k_msleep(2000);
    }

    /* ── 2. Routing stabilisation ────────────────────────────────────────── */
    LOG_INF("Interface up. Waiting 5 s for routing to settle...");
    k_msleep(5000);

    /* ── 3. NTP time sync ────────────────────────────────────────────────── */
    ntp_sync_blocking(K_SECONDS(15));

    /* ── MAC Address Authentication Check ───────────────────────────────── */
    char local_mac[18] = {0};
    ret = get_local_mac_address(local_mac, sizeof(local_mac));
    if (ret != 0) {
        LOG_ERR("Could not read local MAC address: %d. Halting update.", ret);
        return ret;
    }
    LOG_INF("Local Hardware Identifier: %s", local_mac);

    LOG_INF("Checking system operational clearance against remote whitelist...");
    ret = verify_device_authorization(local_mac);
    if (ret != 0) {
        LOG_ERR("Device authorization failed (%d). Aborting OTA process.", ret);
        return ret;
    }
    k_msleep(500);

    /* ── 4. Fetch manifest ───────────────────────────────────────────────── */
    ret = ota_manifest_fetch();
    if (ret != 0) {
        LOG_ERR("Manifest fetch failed: %d", ret);
        return ret;
    }

    const struct ota_manifest *manifest = ota_manifest_get();

    /* ── 5. Version check ────────────────────────────────────────────────── */
    if (ota_manifest_version_cmp(manifest->version, FIRMWARE_VERSION_CURRENT) <= 0) {
        LOG_INF("Already running the latest firmware (%s). Nothing to do.",
                FIRMWARE_VERSION_CURRENT);
        return 0;
    }
    LOG_INF("Update available: %s → %s",
            FIRMWARE_VERSION_CURRENT, manifest->version);

    /* ── 6-8. Download + verify, restarting from scratch on any failure ─── */
    bool update_ready = false;

    for (int attempt = 1; attempt <= OTA_MAX_DOWNLOAD_ATTEMPTS; attempt++) {
        uint32_t computed_crc   = 0;
        size_t   received_bytes = 0;

        LOG_INF("Firmware download attempt %d/%d ...",
                attempt, OTA_MAX_DOWNLOAD_ATTEMPTS);

        ret = ota_download_firmware(manifest, &computed_crc, &received_bytes);
        if (ret != 0) {
            LOG_WRN("Download attempt %d failed (%d).", attempt, ret);
            goto retry_wait;
        }

        ret = ota_download_verify_crc32(manifest, computed_crc, received_bytes);
        if (ret != 0) {
            LOG_WRN("CRC-32 check failed on attempt %d — download was "
                    "corrupted or interrupted.", attempt);
            goto retry_wait;
        }

        ret = ota_download_verify_sha256(manifest);
        if (ret != 0) {
            LOG_WRN("SHA-256 check failed on attempt %d.", attempt);
            goto retry_wait;
        }

        update_ready = true;
        break;

retry_wait:
        if (attempt < OTA_MAX_DOWNLOAD_ATTEMPTS) {
            LOG_INF("Retrying download in %d ms ...", OTA_RETRY_DELAY_MS);
            k_msleep(OTA_RETRY_DELAY_MS);
        }
    }

    if (!update_ready) {
        LOG_ERR("Firmware download/verify failed after %d attempts. "
                "Giving up until next scheduled OTA check.",
                OTA_MAX_DOWNLOAD_ATTEMPTS);
        return -EIO;
    }

    /* ── 9. Request MCUboot upgrade and reboot ───────────────────────────── */
    LOG_INF("Download verified (CRC-32 + SHA-256 OK). "
            "Requesting MCUboot upgrade...");

    ret = boot_request_upgrade(BOOT_UPGRADE_TEST);
    if (ret != 0) {
        LOG_ERR("boot_request_upgrade failed: %d", ret);
        return ret;
    }

    LOG_INF("Rebooting into new firmware in 1 s...");
    k_msleep(1000);
    sys_reboot(SYS_REBOOT_COLD);

    /* Never reached */
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * ota_thread_fn() — persistent worker thread.
 *
 * Blocks on sem_ota_trigger, runs one full OTA pass, then goes straight
 * back to waiting on the semaphore. Whether the pass succeeded, found no
 * update, or failed after retries, the next wake-up only happens via the
 * next k_sem_give() — i.e. the next full OTA_INTERVAL timer expiry. There
 * is no shortened/backoff retry interval after a failure.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void ota_thread_fn(void *arg1, void *arg2, void *arg3)
{
    ARG_UNUSED(arg1);
    ARG_UNUSED(arg2);
    ARG_UNUSED(arg3);

    while (true) {
        k_sem_take(&sem_ota_trigger, K_FOREVER);

        LOG_INF("=== Starting OTA check/update cycle ===");
        int ret = ota_run_once();
        LOG_INF("=== OTA cycle finished (ret=%d). Sleeping until next "
                "scheduled check. ===", ret);
    }
}

K_THREAD_STACK_DEFINE(ota_thread_stack, OTA_THREAD_STACK_SIZE);
static struct k_thread ota_thread_data;

/* ═══════════════════════════════════════════════════════════════════════════
 * MAIN — one-time init only. Periodic OTA work happens in ota_thread_fn().
 * ═══════════════════════════════════════════════════════════════════════════ */
int main(void)
{
    int ret;

    /* Sensor reading replaces the old LED heartbeat — no dk_leds_init()
     * precondition, just start the polling thread directly. */
    sensor_iface_start();

    ret = tls_common_init();
    if (ret < 0) {
        return ret;
    }

    LOG_INF("OTA Client starting. Waiting for Wi-Fi...");

    wifi_net_init();

    /* Block here once at boot so the first OTA pass (triggered by the
     * semaphore's initial count of 1) doesn't race ahead of link-up. The
     * OTA thread itself also calls wifi_net_wait_connected() on every
     * cycle, in case the link has dropped between runs. */
    wifi_net_wait_connected();

    /* ── Start the periodic OTA worker thread ────────────────────────────── */
    k_thread_create(&ota_thread_data,
                    ota_thread_stack,
                    K_THREAD_STACK_SIZEOF(ota_thread_stack),
                    ota_thread_fn,
                    NULL, NULL, NULL,
                    OTA_THREAD_PRIORITY,
                    0,
                    K_NO_WAIT);

    /* ── Start the 24 h recurring trigger ────────────────────────────────── */
    k_timer_start(&ota_timer, OTA_INTERVAL, OTA_INTERVAL);

    LOG_INF("OTA scheduler armed: first check now, then every 24 h.");

    return 0;
}
