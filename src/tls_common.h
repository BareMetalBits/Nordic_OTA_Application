#define TLS_COMMON_H

/*
 * tls_common.h — Shared TLS socket setup used by main.c (manifest fetch,
 * firmware download) and mac_auth.c (whitelist fetch).
 *
 * Extracted verbatim from main.c's open_tls_socket() and the root-CA
 * registration block in main() — no logic changed, only relocated.
 */

#include <stddef.h>

/*
 * Shared TLS security tag — must match the tag used when the root CA
 * credential is registered via tls_common_init(). mac_auth.h previously
 * carried this definition; it now lives here as the single source of truth
 * and mac_auth.h includes this file instead of redefining it.
 */
#define OTA_TLS_SEC_TAG  42

/**
 * @brief Register the ISRG Root X1 certificate under OTA_TLS_SEC_TAG.
 *
 * Must be called once at startup, before any call to tls_common_open_socket()
 * or mac_auth's verify_device_authorization(). Identical in effect to the
 * tls_credential_delete() + tls_credential_add() block previously inlined
 * at the top of main().
 *
 * @return 0 on success, negative errno from tls_credential_add() on failure.
 */
int tls_common_init(void);

/**
 * @brief Open a TLS 1.2 connection to host:port with peer verification.
 *
 * Identical behaviour to the original open_tls_socket() in main.c:
 * DNS resolve → socket(IPPROTO_TLS_1_2) → TLS_SEC_TAG_LIST → TLS_HOSTNAME
 * (SNI) → TLS_PEER_VERIFY_REQUIRED → connect().
 *
 * @param host  Hostname to resolve and connect to.
 * @param port  Port as a string (e.g. "443").
 * @return Socket fd (>= 0) on success, negative errno on failure. Caller
 *         is responsible for close().
 */
int tls_common_open_socket(const char *host, const char *port);
