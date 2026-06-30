/*
 * mac_auth.c — Device MAC-address whitelist authentication
 *
 * Fetches /BareMetalBits/OTA_Nordic/main/allowed_macs.json over HTTPS and
 * checks whether this device's Wi-Fi MAC address appears in the list.
 *
 * Reuses OTA_TLS_SEC_TAG (defined in mac_auth.h) — the root CA credential
 * registered by main() before this function is ever called. No separate
 * tls_credential_add() call is needed here.
 *
 * Call order enforced by main():
 *   1. tls_credential_add()          — root CA registered at startup
 *   2. NTP sync complete             — cert time validation works
 *   3. get_local_mac_address()       — read this device's MAC
 *   4. verify_device_authorization() — fetch + search whitelist
 *   5. fetch_manifest() ...          — proceed only if step 4 returns 0
 */

#include "mac_auth.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

LOG_MODULE_REGISTER(mac_auth, LOG_LEVEL_INF);

/* ── Endpoint ─────────────────────────────────────────────────────────────── */
#define GITHUB_HOST  "raw.githubusercontent.com"
#define GITHUB_PORT  "443"
#define AUTH_PATH    "/BareMetalBits/OTA_Nordic/main/allowed_macs.json"

/*
 * Response buffer: holds the full HTTP response (headers + JSON body).
 * GitHub/Fastly headers: ~700-1000 bytes.
 * JSON body (50 MACs × 22 chars each): ~1100 bytes.
 * 3 KB covers both with headroom. Static (BSS) — no stack cost.
 */
#define AUTH_RESP_BUF_SIZE  3072
static char resp_buf[AUTH_RESP_BUF_SIZE];

/* ── Case-insensitive substring search ───────────────────────────────────── */
/*
 * Returns a pointer to the first occurrence of needle in haystack, ignoring
 * ASCII case. Returns NULL if not found. MAC addresses are stored as
 * uppercase "AA:BB:CC:DD:EE:FF" — this function also accepts lowercase JSON.
 *
 * Returns const char * (not char *) because haystack is const: the caller
 * only needs to test for NULL, never to write through the returned pointer.
 */
static const char *istrstr(const char *haystack, const char *needle)
{
    if (!haystack || !needle || !*needle) {
        return haystack;
    }
    for (; *haystack; haystack++) {
        if (tolower((unsigned char)*haystack) ==
            tolower((unsigned char)*needle)) {
            const char *h = haystack + 1;
            const char *n = needle   + 1;
            while (*h && *n &&
                   tolower((unsigned char)*h) ==
                   tolower((unsigned char)*n)) {
                h++;
                n++;
            }
            if (!*n) {
                return haystack;
            }
        }
    }
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * get_local_mac_address()
 *
 * Reads the default network interface's link-layer address and formats it as
 * "AA:BB:CC:DD:EE:FF\0" (uppercase hex, colon-separated, 18 chars total).
 *
 * The MAC is logged at INF so you can immediately read it from the terminal
 * and copy it into allowed_macs.json — no separate tool needed.
 * ═══════════════════════════════════════════════════════════════════════════ */
int get_local_mac_address(char *mac_str, size_t max_len)
{
    if (!mac_str || max_len < 18) {
        return -EINVAL;
    }

    struct net_if *iface = net_if_get_default();
    if (!iface) {
        LOG_ERR("No default network interface available.");
        return -ENODEV;
    }

    struct net_linkaddr *link = net_if_get_link_addr(iface);
    if (!link || link->len != 6) {
        LOG_ERR("Link-layer address unavailable or not 6 bytes.");
        return -EINVAL;
    }

    snprintf(mac_str, max_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             link->addr[0], link->addr[1], link->addr[2],
             link->addr[3], link->addr[4], link->addr[5]);

    LOG_INF("Device MAC: %s  (add to allowed_macs.json if auth is denied)",
            mac_str);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════════
 * verify_device_authorization()
 *
 * Downloads allowed_macs.json over HTTPS (TLS_PEER_VERIFY_REQUIRED, ISRG
 * Root X1 credential) and performs a case-insensitive search for local_mac
 * in the JSON body.
 *
 * Returns  0        authorised
 *         -EACCES   MAC not found in whitelist
 *         other     network / TLS / protocol error
 * ═══════════════════════════════════════════════════════════════════════════ */
int verify_device_authorization(const char *local_mac)
{
    if (!local_mac || !*local_mac) {
        return -EINVAL;
    }

    /* ── DNS + TLS ──────────────────────────────────────────────────────── */
    struct addrinfo hints = {
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    struct addrinfo *res = NULL;

    int ret = getaddrinfo(GITHUB_HOST, GITHUB_PORT, &hints, &res);
    if (ret != 0) {
        LOG_ERR("DNS lookup failed for %s: %d", GITHUB_HOST, ret);
        return -EIO;
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (sock < 0) {
        LOG_ERR("TLS socket create failed, errno %d", errno);
        freeaddrinfo(res);
        return -errno;
    }

    sec_tag_t sec_tags[] = { OTA_TLS_SEC_TAG };
    setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,  sec_tags, sizeof(sec_tags));
    setsockopt(sock, SOL_TLS, TLS_HOSTNAME, GITHUB_HOST, strlen(GITHUB_HOST));
    int verify = TLS_PEER_VERIFY_REQUIRED;
    setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY, &verify, sizeof(verify));

    ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (ret < 0) {
        LOG_ERR("TLS connect to %s:%s failed, errno %d",
                GITHUB_HOST, GITHUB_PORT, errno);
        close(sock);
        return -errno;
    }

    LOG_INF("TLS connected to %s for MAC auth", GITHUB_HOST);

    /* ── HTTP GET ──────────────────────────────────────────────────────── */
    char req[256];
    int  req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        AUTH_PATH, GITHUB_HOST);

    if (send(sock, req, req_len, 0) < 0) {
        LOG_ERR("send() failed, errno %d", errno);
        close(sock);
        return -errno;
    }

    /* ── Receive full response ─────────────────────────────────────────── */
    memset(resp_buf, 0, sizeof(resp_buf));
    size_t total       = 0;
    bool   peer_closed = false;
    int    n;

    while (total < sizeof(resp_buf) - 1) {
        n = recv(sock, resp_buf + total,
                 sizeof(resp_buf) - 1 - total, 0);
        if (n < 0) {
            LOG_ERR("recv() failed, errno %d", errno);
            close(sock);
            return -errno;
        }
        if (n == 0) {
            peer_closed = true;
            break; /* server closed — all data received */
        }
        total += n;
    }
    close(sock);

    if (!peer_closed) {
        /*
         * Buffer filled before the server closed — the JSON body is truncated.
         * A truncated search could produce a false negative (legitimate device
         * gets denied). Fail loudly rather than silently authorise or deny.
         * Fix: increase AUTH_RESP_BUF_SIZE or trim the whitelist JSON.
         */
        LOG_ERR("Auth response buffer full (%d B) before server EOF — "
                "whitelist may be truncated. Increase AUTH_RESP_BUF_SIZE.",
                AUTH_RESP_BUF_SIZE);
        return -EMSGSIZE;
    }

    resp_buf[total] = '\0';

    /* ── Locate HTTP body ──────────────────────────────────────────────── */
    char *body = strstr(resp_buf, "\r\n\r\n");
    if (!body) {
        LOG_ERR("No HTTP header/body separator in auth response.");
        return -EPROTO;
    }
    body += 4;

    /* ── MAC search ────────────────────────────────────────────────────── */
    /*
     * Scan the raw JSON body for the MAC string (case-insensitive).
     * A 17-character MAC address "AA:BB:CC:DD:EE:FF" is a fixed length and
     * cannot be a proper prefix of another valid MAC, so strstr produces no
     * false positives in well-formed JSON.
     *
     * Supported JSON format (any order, extra fields ignored):
     *   {
     *     "allowed_macs": [
     *       "AA:BB:CC:DD:EE:FF",
     *       "11:22:33:44:55:66"
     *     ]
     *   }
     */
    if (istrstr(body, local_mac) != NULL) {
        LOG_INF("MAC auth PASSED: %s is authorised.", local_mac);
        return 0;
    }

    LOG_ERR("MAC auth DENIED: %s not found in whitelist.", local_mac);
    return -EACCES;
}
