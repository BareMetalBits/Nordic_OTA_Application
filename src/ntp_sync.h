#define NTP_SYNC_H

#include <zephyr/kernel.h>

/*
 * ntp_sync.h — NTP time sync wrapper.
 *
 * Extracted from main.c: on_date_time_notification(), sem_ntp_done, and
 * the date_time_register_handler() / date_time_update_async() / k_sem_take
 * sequence that was inlined in main(). Logic is unchanged; the only
 * difference is the 15-second timeout is now a function parameter instead
 * of a hardcoded K_SECONDS(15), to avoid a magic number crossing the
 * module boundary silently. Calling with the same value reproduces
 * identical behaviour.
 */

/**
 * @brief Start an NTP sync and block until it completes or times out.
 *
 * On timeout, logs the same warning the original main() logged and returns
 * normally — NTP failure is non-fatal, exactly as before.
 *
 * @param timeout  How long to wait for sync (pass K_SECONDS(15) to match
 *                 the original main.c behaviour exactly).
 */
void ntp_sync_blocking(k_timeout_t timeout);

