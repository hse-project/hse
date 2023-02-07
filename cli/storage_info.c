/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <errno.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>

#include <hse/hse.h>
#include <hse/cli/rest/api.h>
#include <hse/cli/rest/client.h>
#include <hse/cli/tprint.h>
#include <hse/pidfile/pidfile.h>

#include <hse/util/assert.h>
#include <hse/util/base.h>
#include <hse/util/compiler.h>

int
hse_storage_info(const char *const kvdb_home)
{
    static const char *const headers[] = { "MEDIA_CLASS", "ALLOCATED_BYTES", "USED_BYTES", "PATH" };
    static const enum tprint_justify justify[] = { TP_JUSTIFY_LEFT, TP_JUSTIFY_RIGHT,
        TP_JUSTIFY_RIGHT, TP_JUSTIFY_LEFT };

    hse_err_t               err = 0;
    struct hse_kvdb *       kvdb = NULL;
    struct hse_mclass_info  info[HSE_MCLASS_COUNT];
    int                     rc = 0;
    unsigned int            rowid;
    struct pidfile          content;
    char                    nums[HSE_MCLASS_COUNT][2][21];
    const char *            values[NELEM(headers) * HSE_MCLASS_COUNT];
    HSE_MAYBE_UNUSED size_t n;
    bool                    mc_present[HSE_MCLASS_COUNT] = { 0 };
    bool                    used_rest = false;
    char                    buf[256];

    INVARIANT(kvdb_home);

    err = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (!err) {
        for (enum hse_mclass i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
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
        err = pidfile_deserialize(kvdb_home, &content);
        if (err)
            goto out;

        if (content.rest.socket_path[0] == '\0') {
            err = ENOENT;
            fprintf(stderr, "HSE socket is disabled in PID %d\n", content.pid);
            goto out;
        }

        err = rest_client_init(content.rest.socket_path);
        if (err) {
            fprintf(stderr, "Failed to initialize the rest client\n");
            goto out;
        }

        used_rest = true;

        for (enum hse_mclass i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
            err = rest_kvdb_get_mclass_info(&info[i], content.alias, i);
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
    } else {
        if (hse_err_to_errno(err) == ENOENT)
            fprintf(stderr, "No such KVDB (%s)\n", kvdb_home);
        else {
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Unable to open KVDB, %s\n", buf);
        }
        goto out;
    }

    rowid = 0;
    for (enum hse_mclass i = HSE_MCLASS_BASE; i < HSE_MCLASS_COUNT; i++) {
        if (mc_present[i]) {
            const size_t base = rowid * NELEM(headers);
            values[base] = hse_mclass_name_get(i);

            rc = snprintf(nums[rowid][0], sizeof(nums[rowid][0]), "%lu",
                          info[i].mi_allocated_bytes);
            if (rc < 0) {
                rc = EBADMSG;
                goto out;
            } else if (rc >= sizeof(nums[rowid][0])) {
                rc = EMSGSIZE;
                goto out;
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

    err = tprint(stdout, rowid, NELEM(headers), headers, values, justify, NULL);

out:
    if (used_rest)
        rest_client_fini();

    if (kvdb)
        hse_kvdb_close(kvdb);

    return rc ? rc : hse_err_to_errno(err);
}
