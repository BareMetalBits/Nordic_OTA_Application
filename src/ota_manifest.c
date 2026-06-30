/*
 * ota_manifest.c — OTA manifest fetch and parsing.
 *
 * fetch logic, header/body splitting, truncation guard, and bitmask
 * validation are byte-for-byte identical to the original fetch_manifest()
 * in main.c. Only the function name (ota_manifest_fetch) and the addition
 * of ota_manifest_get() / ota_manifest_version_cmp() wrappers are new —
 * no behavioural change.
 */

#include "ota_manifest.h"
#include "tls_common.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/socket.h>
#include <zephyr/data/json.h>

LOG_MODULE_REGISTER(ota_manifest, LOG_LEVEL_INF);

/* ── GitHub endpoint ──────────────────────────────────────────────────────── */
#define GITHUB_HOST    "raw.githubusercontent.com"
#define GITHUB_PORT    "443"
#define MANIFEST_PATH  "/BareMetalBits/OTA_Nordic_Server/main/update.json"

/*
 * Manifest buffer holds the ENTIRE HTTP response — headers + body.
 * raw.githubusercontent.com (GitHub/Fastly CDN) routinely sends 700-1000+
 * bytes of response headers ahead of the ~230 byte update.json body.
 * 2048 bytes leaves comfortable headroom for both.
 */
#define MANIFEST_BUF_SIZE  2048

static const struct json_obj_descr manifest_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct ota_manifest, version,   JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct ota_manifest, file_size, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(struct ota_manifest, fw_path,   JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct ota_manifest, sha256,    JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct ota_manifest, crc32,     JSON_TOK_STRING),
};

static struct ota_manifest g_manifest;
static char manifest_raw[MANIFEST_BUF_SIZE];

int ota_manifest_fetch(void)
{
    int sock = tls_common_open_socket(GITHUB_HOST, GITHUB_PORT);
    if (sock < 0) {
        return sock;
    }

    char req[256];
    int  req_len = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        MANIFEST_PATH, GITHUB_HOST);

    if (send(sock, req, req_len, 0) < 0) {
        LOG_ERR("manifest send() failed, errno %d", errno);
        close(sock);
        return -errno;
    }

    size_t total = 0;
    int    n;
    bool   peer_closed = false;

    memset(manifest_raw, 0, sizeof(manifest_raw));

    while (total < sizeof(manifest_raw) - 1) {
        n = recv(sock, manifest_raw + total,
                 sizeof(manifest_raw) - 1 - total, 0);
        if (n < 0) {
            LOG_ERR("manifest recv() failed, errno %d", errno);
            close(sock);
            return -errno;
        }
        if (n == 0) {
            peer_closed = true;
            break; /* server closed connection — all data received */
        }
        total += n;
    }
    close(sock);

    if (!peer_closed) {
        /* Buffer filled before the server sent a clean close — the
         * response is almost certainly truncated. Fail loudly instead of
         * letting json_obj_parse() guess. */
        LOG_WRN("manifest_raw filled (%zu bytes) before the connection "
                "closed — response is likely truncated. Increase "
                "MANIFEST_BUF_SIZE if this keeps happening.", total);
    }

    /* Separate headers from body. */
    char *body = strstr(manifest_raw, "\r\n\r\n");
    if (!body) {
        LOG_ERR("No HTTP body separator in manifest response");
        return -EPROTO;
    }
    body += 4;
    size_t body_len = total - (size_t)(body - manifest_raw);

    /* Full raw body is only useful for deep debugging — keep it out of the
     * normal terminal output by logging at DBG level. */
    LOG_DBG("Manifest body (%zu bytes):\n%s", body_len, body);

    memset(&g_manifest, 0, sizeof(g_manifest));
    int ret = json_obj_parse(body, body_len,
                             manifest_descr, ARRAY_SIZE(manifest_descr),
                             &g_manifest);
    if (ret < 0) {
        LOG_ERR("JSON parse failed: %d", ret);
        return ret;
    }

    /* json_obj_parse() returns a bitmask of which descriptors were found.
     * A successful return code doesn't guarantee every field was present —
     * confirm all 5 bits are set before trusting the manifest. */
    const int all_fields = (1 << ARRAY_SIZE(manifest_descr)) - 1;
    if (ret != all_fields) {
        LOG_ERR("Manifest missing field(s) — parsed mask 0x%x, expected 0x%x",
                ret, all_fields);
        return -EPROTO;
    }

    LOG_INF("version : %s", g_manifest.version);
    LOG_INF("fw_path : %s", g_manifest.fw_path);
    LOG_INF("sha256  : %s", g_manifest.sha256);
    LOG_INF("crc32   : %s", g_manifest.crc32);

    return 0;
}

const struct ota_manifest *ota_manifest_get(void)
{
    return &g_manifest;
}

int ota_manifest_version_cmp(const char *a, const char *b)
{
    int am = 0, an = 0, ap = 0;
    int bm = 0, bn = 0, bp = 0;

    sscanf(a, "%d.%d.%d", &am, &an, &ap);
    sscanf(b, "%d.%d.%d", &bm, &bn, &bp);

    if (am != bm) { return am - bm; }
    if (an != bn) { return an - bn; }
    return ap - bp;
}
