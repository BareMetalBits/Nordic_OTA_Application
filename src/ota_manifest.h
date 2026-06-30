#define OTA_MANIFEST_H

/*
 * ota_manifest.h — OTA manifest (update.json) fetch and parsing.
 *
 * Extracted from main.c: struct ota_manifest, manifest_descr[],
 * manifest_raw[], g_manifest, find_body_start(), version_cmp(),
 * fetch_manifest(). All logic identical to the original.
 *
 * struct ota_manifest is exposed here (not kept private) because both
 * main.c (version_cmp against FIRMWARE_VERSION_CURRENT) and
 * ota_download.c (fw_path, file_size, sha256, crc32) need direct field
 * access — exactly the same fields g_manifest exposed before the split.
 */

/*
 * IMPORTANT: the string fields below are `const char *`, NOT fixed arrays.
 * Zephyr's json_obj_parse() does not copy strings — decode_string() just
 * NUL-terminates the value in place inside the internal manifest_raw[]
 * buffer and stores a POINTER to it in the destination field. Because that
 * buffer is `static` inside ota_manifest.c, it lives for the program's
 * lifetime, so these pointers stay valid after ota_manifest_fetch() returns.
 */
struct ota_manifest {
    const char *version;
    int         file_size;
    const char *fw_path;
    const char *sha256;
    const char *crc32;
};

/**
 * @brief Fetch and parse update.json from GitHub over TLS.
 *
 * Identical behaviour to the original fetch_manifest(): HTTP/1.1 GET with
 * Connection: close, truncation guard via peer_closed tracking, 5-field
 * bitmask validation after json_obj_parse().
 *
 * On success, the manifest fields are accessible via ota_manifest_get().
 *
 * @return 0 on success, negative errno on failure (-EIO, -EPROTO, parser
 *         error codes from json_obj_parse).
 */
int ota_manifest_fetch(void);

/**
 * @brief Get a pointer to the most recently fetched manifest.
 *
 * Valid only after a successful ota_manifest_fetch() call. The returned
 * pointer references static storage inside ota_manifest.c — do not free it,
 * and treat it as read-only.
 *
 * @return Pointer to the internal manifest struct.
 */
const struct ota_manifest *ota_manifest_get(void);

/**
 * @brief Compare two "MAJOR.MINOR.PATCH" version strings.
 *
 * Identical to the original version_cmp() in main.c.
 *
 * @return > 0 if a > b, 0 if equal, < 0 if a < b.
 */
int ota_manifest_version_cmp(const char *a, const char *b);
