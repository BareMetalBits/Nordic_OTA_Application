#define WIFI_NET_H

#include <stdbool.h>

/*
 * wifi_net.h — Wi-Fi L4 connection state.
 *
 * Extracted from main.c: net_mgmt_event_handler(), L4_EVENTS, sem_l4_up,
 * mgmt_cb. Logic is unchanged — only the blocking wait is wrapped in a
 * named function so main() doesn't reach into the semaphore directly.
 */

/**
 * @brief Register the L4 connected/disconnected net_mgmt callback.
 * Must be called once before wifi_net_wait_connected().
 */
void wifi_net_init(void);

/**
 * @brief Block until NET_EVENT_L4_CONNECTED fires (Wi-Fi up + DHCP done).
 *
 * Identical to the original `k_sem_take(&sem_l4_up, K_FOREVER);` call in
 * main() — blocks forever, same semaphore, same event source.
 *
 * NOTE: the underlying semaphore is one-shot per connect/disconnect cycle.
 * Call this only once per "boot up and wait for first connect" — for
 * repeated polling (e.g. from a periodic worker thread) use
 * wifi_net_is_connected() instead, or the link-up event will never refire
 * and this call will block forever.
 */
void wifi_net_wait_connected(void);

/**
 * @brief Non-blocking check of current Wi-Fi/L4 connection state.
 *
 * Reflects the most recent NET_EVENT_L4_CONNECTED / NET_EVENT_L4_DISCONNECTED
 * event — safe to call repeatedly (e.g. once per periodic OTA cycle) without
 * the one-shot blocking limitation of wifi_net_wait_connected().
 *
 * @return true if currently connected (Wi-Fi up + DHCP done), false otherwise.
 */
bool wifi_net_is_connected(void);