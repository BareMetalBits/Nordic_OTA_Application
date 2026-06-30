#ifndef MAC_AUTH_H
#define MAC_AUTH_H

#include <stddef.h>
#include "tls_common.h"

/*
 * OTA_TLS_SEC_TAG is now defined in tls_common.h (single source of truth
 * for the shared TLS credential tag, used by main.c, tls_common.c, and
 * mac_auth.c). Pulled in transitively via the include above — no
 * redefinition needed here.
 */

/**
 * @brief Read the Wi-Fi interface MAC address as an uppercase hex string.
 *
 * Format: "AA:BB:CC:DD:EE:FF\0"  — caller must supply at least 18 bytes.
 * The address is also logged at INF level for easy copy-paste into
 * allowed_macs.json when setting up a new board.
 *
 * @param mac_str  Output buffer (minimum 18 bytes).
 * @param max_len  Size of mac_str.
 * @return 0 on success, -ENODEV if no interface, -EINVAL if buffer too small.
 */
int get_local_mac_address(char *mac_str, size_t max_len);

/**
 * @brief Fetch allowed_macs.json and verify this device is listed.
 *
 * Opens a TLS 1.2 connection to raw.githubusercontent.com, downloads
 * /BareMetalBits/OTA_Nordic/main/allowed_macs.json, and performs a
 * case-insensitive search for local_mac in the JSON body.
 *
 * Prerequisites (enforced by call order in main()):
 *   - tls_credential_add() has been called for OTA_TLS_SEC_TAG
 *   - NTP sync has completed so cert time validation works
 *
 * @param local_mac  Null-terminated MAC from get_local_mac_address().
 * @return  0          authorised
 *         -EACCES     MAC not found in whitelist
 *         -EMSGSIZE   auth response truncated (increase AUTH_RESP_BUF_SIZE)
 *         other       network / TLS / protocol error
 */
int verify_device_authorization(const char *local_mac);

#endif /* MAC_AUTH_H */
