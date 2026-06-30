/*
 * ntp_sync.c — NTP time sync wrapper.
 *
 * on_date_time_notification() body is byte-for-byte identical to the
 * original in main.c.
 */

#include "ntp_sync.h"

#include <zephyr/logging/log.h>
#include <date_time.h>

LOG_MODULE_REGISTER(ntp_sync, LOG_LEVEL_INF);

static K_SEM_DEFINE(sem_ntp_done, 0, 1);

static void on_date_time_notification(const struct date_time_evt *evt)
{
    if (evt->type == DATE_TIME_OBTAINED_NTP) {
        LOG_INF("NTP sync successful.");
    } else {
        LOG_WRN("NTP sync failed — TLS cert time check may fail if cert "
                "window has shifted.");
    }
    k_sem_give(&sem_ntp_done);
}

void ntp_sync_blocking(k_timeout_t timeout)
{
    LOG_INF("Starting NTP sync...");
    date_time_register_handler(on_date_time_notification);
    date_time_update_async(NULL);

    if (k_sem_take(&sem_ntp_done, timeout) != 0) {
        LOG_WRN("NTP timed out — TLS cert time check may fail if cert expired");
    }
}
