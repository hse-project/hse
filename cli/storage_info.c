/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>

#include <cli/tprint.h>

#include <hse/hse.h>
#include <hse_util/base.h>
#include <hse_util/invariant.h>
#include <hse_util/rest_client.h>

#include <pidfile/pidfile.h>

static const char *const media_classes[] = {
    HSE_MCLASS_CAPACITY_NAME, HSE_MCLASS_STAGING_NAME, HSE_MCLASS_PMEM_NAME
};

int
hse_storage_info(const char *const kvdb_home)
{
    static const char *const headers[] = { "MEDIA_CLASS", "ALLOCATED_BYTES", "USED_BYTES", "PATH" };

    hse_err_t               err = 0;
    struct hse_kvdb *       kvdb = NULL;
    struct hse_mclass_info  info[NELEM(media_classes)];
    int                     rc = 0;
    struct pidfile          content;
    char                    url[128];
    char                    buf[1024];
    char                    nums[NELEM(media_classes)][2][21];
    const char *            values[NELEM(headers) * NELEM(media_classes)];
    cJSON *                 root;
    HSE_MAYBE_UNUSED size_t n;

    INVARIANT(kvdb_home);
    INVARIANT(media_class);

    err = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (!err) {
        for (size_t i = 0; i < NELEM(media_classes); i++) {
            err = hse_kvdb_mclass_info_get(kvdb, media_classes[i], &info[i]);
            if (err) {
                if (hse_err_to_errno(err) == ENOENT) {
                    err = 0;
                    continue;
                }

                goto out;
            }
        }
    } else if (err && hse_err_to_errno(err) == EBUSY) {
        rc = pidfile_deserialize(kvdb_home, &content);
        if (rc)
            goto out;

        for (size_t i = 0; i < NELEM(media_classes); i++) {
            struct hse_mclass_info *data = &info[i];

            rc = snprintf(
                url, sizeof(url), "kvdb/%s/mclass/%s/info", content.alias, media_classes[i]);
            if (rc < 0) {
                rc = EBADMSG;
                goto out;
            }

            assert(rc < sizeof(url));

            err = curl_get(url, content.socket.path, buf, sizeof(buf));
            if (err)
                goto out;

            /* Because of issues with the REST server, and the way this
             * curl_get() function is implemented, I cannot return what would
             * ideally be a 404 status in which I could find out whether the
             * media class was configured or not. To overcome this, if the
             * following parse fails, then we assume that it is because no data
             * was written into the buffer, meaning the media class was not
             * configured.
             */
            root = cJSON_Parse(buf);
            if (!root) {
                if (cJSON_GetErrorPtr()) {
                    continue;
                } else {
                    rc = ENOMEM;
                    goto out;
                }
            }

            n = strlcpy(
                data->mi_path, cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(root, "path")),
                sizeof(data->mi_path));
            assert(n < sizeof(data->mi_path));
            data->mi_allocated_bytes = cJSON_GetNumberValue(
                cJSON_GetObjectItemCaseSensitive(root, "allocated_bytes"));
            data->mi_used_bytes = cJSON_GetNumberValue(
                cJSON_GetObjectItemCaseSensitive(root, "used_bytes"));
        }
    } else {
        return hse_err_to_errno(err);
    }

    for (size_t i = 0; i < NELEM(media_classes); i++) {
        const int base = i * NELEM(headers);
        values[base] = media_classes[i];

        rc = snprintf(nums[i][0], sizeof(nums[i][0]), "%lu", info[i].mi_allocated_bytes);
        if (rc < 0) {
            rc = EBADMSG;
            goto out;
        } else if (rc >= sizeof(nums[i][0])) {
            rc = EMSGSIZE;
            goto out;
        } else {
            rc = 0;
        }
        values[base + 1] = nums[i][0];

        rc = snprintf(nums[i][1], sizeof(nums[i][1]), "%lu", info[i].mi_used_bytes);
        if (rc < 0) {
            rc = EBADMSG;
            goto out;
        } else if (rc >= sizeof(nums[i][0])) {
            rc = EMSGSIZE;
            goto out;
        } else {
            rc = 0;
        }
        values[base + 2] = nums[i][1];

        values[base + 3] = info[i].mi_path;
    }

    tprint(stdout, NELEM(media_classes), NELEM(headers), headers,
        values, NULL);

out:
    if (kvdb)
        hse_kvdb_close(kvdb);

    return rc ? rc : hse_err_to_errno(err);
}
