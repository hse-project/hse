/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>

#include <cli/tprint.h>

#include <hse/hse.h>
#include <hse_util/assert.h>
#include <hse_util/base.h>
#include <hse_util/rest_client.h>

#include <pidfile/pidfile.h>

int
hse_storage_info(const char *const kvdb_home)
{
    static const char *const headers[] = { "MEDIA_CLASS", "ALLOCATED_BYTES", "USED_BYTES", "PATH" };

    hse_err_t               err = 0;
    struct hse_kvdb *       kvdb = NULL;
    struct hse_mclass_info  info[HSE_MCLASS_COUNT];
    int                     rc = 0, rowid;
    struct pidfile          content;
    char                    url[128];
    char                    buf[1024];
    char                    nums[HSE_MCLASS_COUNT][2][21];
    const char *            values[NELEM(headers) * HSE_MCLASS_COUNT];
    HSE_MAYBE_UNUSED size_t n;
    bool                    mc_present[HSE_MCLASS_COUNT] = { 0 };

    INVARIANT(kvdb_home);

    err = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (!err) {
        for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
            err = hse_kvdb_mclass_info_get(kvdb, i, &info[i]);
            if (err) {
                if (hse_err_to_errno(err) == ENOENT) {
                    err = 0;
                    continue;
                }

                goto out;
            }

            if (info[i].mi_allocated_bytes > 0)
                mc_present[i] = true;
        }
    } else if (err && hse_err_to_errno(err) == EBUSY) {
        rc = pidfile_deserialize(kvdb_home, &content);
        if (rc)
            goto out;

        for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
            cJSON *root;
            struct hse_mclass_info *data = &info[i];

            memset(data, 0, sizeof(*data));

            rc = snprintf(
                url, sizeof(url), "kvdb/%s/mclass/%s/info", content.alias, hse_mclass_name_get(i));
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

            if (data->mi_allocated_bytes > 0)
                mc_present[i] = true;

            cJSON_Delete(root);
        }
    } else {
        if (hse_err_to_errno(err) == ENOENT)
            fprintf(stderr, "No such KVDB (%s)\n", kvdb_home);
        return hse_err_to_errno(err);
    }

    rowid = 0;
    for (int i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (mc_present[i]) {
            const int base = rowid * NELEM(headers);
            values[base] = hse_mclass_name_get(i);

            rc = snprintf(nums[rowid][0], sizeof(nums[rowid][0]), "%lu",
                          info[i].mi_allocated_bytes);
            if (rc < 0) {
                rc = EBADMSG;
                goto out;
            } else if (rc >= sizeof(nums[rowid][0])) {
                rc = EMSGSIZE;
                goto out;
            } else {
                rc = 0;
            }
            values[base + 1] = nums[rowid][0];

            rc = snprintf(nums[rowid][1], sizeof(nums[rowid][1]), "%lu", info[i].mi_used_bytes);
            if (rc < 0) {
                rc = EBADMSG;
                goto out;
            } else if (rc >= sizeof(nums[rowid][1])) {
                rc = EMSGSIZE;
                goto out;
            } else {
                rc = 0;
            }
            values[base + 2] = nums[rowid][1];

            values[base + 3] = info[i].mi_path;

            rowid++;
        }
    }

    tprint(stdout, rowid, NELEM(headers), headers, values, NULL);

out:
    if (kvdb)
        hse_kvdb_close(kvdb);

    return rc ? rc : hse_err_to_errno(err);
}
