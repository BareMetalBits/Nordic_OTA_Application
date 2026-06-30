/*
 * wifi_net.c — Wi-Fi L4 connection state.
 *
 * net_mgmt_event_handler() body is byte-for-byte identical to the version
 * in the original main.c, including the uint64_t mgmt_event parameter type
 * (correct for Zephyr 4.2.x net_mgmt_event_handler_t — do not change to
 * uint32_t, it will not compile).
 */

#include "wifi_net.h"

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/wifi_mgmt.h>
#include <zephyr/net/net_if.h>

LOG_MODULE_REGISTER(wifi_net, LOG_LEVEL_INF);

#define L4_EVENTS (NET_EVENT_L4_CONNECTED | NET_EVENT_L4_DISCONNECTED)

static K_SEM_DEFINE(sem_l4_up, 0, 1);
static struct net_mgmt_event_callback mgmt_cb;

/*
 * sem_l4_up is one-shot per connect event — fine for the single boot-time
 * wifi_net_wait_connected() call, but useless for repeated polling (e.g.
 * once per periodic OTA cycle), since it won't be given again as long as
 * the link stays up. wifi_connected mirrors the same event stream as a
 * persistent flag so it can be checked non-blockingly, any number of times.
 */
static atomic_t wifi_connected = ATOMIC_INIT(0);

static void net_mgmt_event_handler(struct net_mgmt_event_callback *cb,
                                   uint64_t mgmt_event,
                                   struct net_if *iface)
{
    if ((mgmt_event & L4_EVENTS) != mgmt_event) {
        return;
    }
    if (mgmt_event == NET_EVENT_L4_CONNECTED) {
        LOG_INF("Wi-Fi connected & IP assigned.");
        atomic_set(&wifi_connected, 1);
        k_sem_give(&sem_l4_up);
    } else if (mgmt_event == NET_EVENT_L4_DISCONNECTED) {
        LOG_WRN("Wi-Fi disconnected.");
        atomic_set(&wifi_connected, 0);
        k_sem_reset(&sem_l4_up);
    }
}

void wifi_net_init(void)
{
    net_mgmt_init_event_callback(&mgmt_cb, net_mgmt_event_handler, L4_EVENTS);
    net_mgmt_add_event_callback(&mgmt_cb);
}

void wifi_net_wait_connected(void)
{
    k_sem_take(&sem_l4_up, K_FOREVER);
}

bool wifi_net_is_connected(void)
{
    return atomic_get(&wifi_connected) != 0;
}