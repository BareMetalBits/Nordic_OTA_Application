/*
 * tls_common.c — Shared TLS socket setup.
 *
 * Body of tls_common_open_socket() is byte-for-byte identical to the
 * original open_tls_socket() in main.c. tls_common_init() is byte-for-byte
 * identical to the tls_credential_delete()/tls_credential_add() block that
 * was previously inlined at the top of main(). ota_root_ca[] is unchanged.
 */

#include "tls_common.h"

#include <errno.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/socket.h>
#include <zephyr/net/tls_credentials.h>

LOG_MODULE_REGISTER(tls_common, LOG_LEVEL_INF);

/* ── ISRG Root X1 — Root CA for raw.githubusercontent.com ────────────────── */
static const char ota_root_ca[] =
    "-----BEGIN CERTIFICATE-----\n"
    "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\n"
    "Cc=\n"
    "-----END CERTIFICATE-----\n";

int tls_common_init(void)
{
    tls_credential_delete(OTA_TLS_SEC_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
    int ret = tls_credential_add(OTA_TLS_SEC_TAG, TLS_CREDENTIAL_CA_CERTIFICATE,
                                 ota_root_ca, sizeof(ota_root_ca));
    if (ret < 0) {
        LOG_ERR("tls_credential_add failed: %d", ret);
    }
    return ret;
}

int tls_common_open_socket(const char *host, const char *port)
{
    struct addrinfo hints = {
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = IPPROTO_TCP,
    };
    struct addrinfo *res = NULL;

    int ret = getaddrinfo(host, port, &hints, &res);
    if (ret != 0) {
        LOG_ERR("DNS lookup failed for %s: %d", host, ret);
        return -EIO;
    }

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TLS_1_2);
    if (sock < 0) {
        LOG_ERR("TLS socket create failed, errno %d", errno);
        freeaddrinfo(res);
        return -errno;
    }

    sec_tag_t sec_tags[] = { OTA_TLS_SEC_TAG };
    setsockopt(sock, SOL_TLS, TLS_SEC_TAG_LIST,
               sec_tags, sizeof(sec_tags));

    setsockopt(sock, SOL_TLS, TLS_HOSTNAME,
               host, strlen(host));

    int verify = TLS_PEER_VERIFY_REQUIRED;
    setsockopt(sock, SOL_TLS, TLS_PEER_VERIFY,
               &verify, sizeof(verify));

    ret = connect(sock, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    if (ret < 0) {
        LOG_ERR("TLS connect to %s:%s failed, errno %d", host, port, errno);
        close(sock);
        return -errno;
    }

    LOG_INF("TLS connected to %s", host);
    return sock;
}
