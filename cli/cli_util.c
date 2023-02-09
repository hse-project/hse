/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include <hse/experimental.h>
#include <hse/hse.h>

#include <hse/cli/rest/api.h>
#include <hse/cli/rest/client.h>
#include <hse/error/merr.h>
#include <hse/pidfile/pidfile.h>
#include <hse/util/arch.h>
#include <hse/util/base.h>
#include <hse/util/parse_num.h>

#include "cli_util.h"

static hse_err_t
kvdb_info_props(const char *kvdb_home, const size_t paramc, const char * const *paramv)
{
    size_t namec;
    char **namev;
    hse_err_t err;
    struct hse_kvdb *hdl;
    struct pidfile content;
    bool used_rest = false;

    err = hse_kvdb_open(kvdb_home, paramc, paramv, &hdl);
    if (err && hse_err_to_errno(err) != EBUSY)
        return err;

    if (err) {
        err = pidfile_deserialize(kvdb_home, &content);
        if (err) {
            fprintf(
                stderr,
                "Failed to find the REST UNIX socket for the KVDB (%s). Ensure the KVDB is open in "
                "a process.\n",
                kvdb_home);
            return err;
        }

        if (content.rest.socket_path[0] == '\0') {
            err = ENOENT;
            fprintf(stderr, "HSE socket is disabled in PID %d\n", content.pid);
            return err;
        }

        err = rest_client_init(content.rest.socket_path);
        if (err) {
            fprintf(stderr, "Failed to initialize the rest client\n");
            return err;
        }

        used_rest = true;

        err = rest_kvdb_get_kvs_names(&namec, &namev, content.alias);
        if (err)
            goto out;
    } else {
        err = hse_kvdb_kvs_names_get(hdl, &namec, &namev);
        if (err)
            goto out;
    }

    for (size_t i = 0; i < namec; i++)
        printf("%s\n", namev[i]);

out:
    if (!used_rest) {
        hse_kvdb_kvs_names_free(hdl, namev);
        hse_kvdb_close(hdl);
    } else {
        rest_kvdb_free_kvs_names(namev);
        rest_client_fini();
    }

    return err;
}

hse_err_t
kvdb_info_print(const char *kvdb_home, const size_t paramc, const char * const *paramv)
{
    hse_err_t err;

    err = kvdb_info_props(kvdb_home, paramc, paramv);
    if (err) {
        char buf[256];
        hse_strerror(err, buf, sizeof(buf));
        fprintf(stderr, "Failed to get KVDB (%s) info: %s\n", kvdb_home, buf);
    }

    return err;
}

int
kvdb_compact_request(const char *kvdb_home, enum kvdb_compact_request request, uint32_t timeout_sec)
{
    hse_err_t err;
    struct hse_kvdb *handle = 0;
    struct hse_kvdb_compact_status status;
    struct pidfile content;

    uint64_t stop_ts;
    uint sleep_secs = 2;
    char **namev;
    size_t namec;
    size_t kvdb_paramc = 0;
    const char *kvdb_paramv[1] = { 0 };
    size_t kvs_paramc = 0;
    const char *kvs_paramv[1] = { 0 };

    /* Full compactions need a few extra params.
     */
    if (request == REQ_COMPACT_FULL) {
        kvdb_paramv[kvdb_paramc++] = "csched_full_compact=true";
        assert(kvdb_paramc <= NELEM(kvdb_paramv));
        kvs_paramv[kvs_paramc++] = "cn_close_wait=true";
        assert(kvs_paramc <= NELEM(kvs_paramv));
    }

    err = hse_kvdb_open(kvdb_home, kvdb_paramc, kvdb_paramv, &handle);
    if (err) {
        handle = 0;
        if (hse_err_to_errno(err) == EBUSY && request == REQ_COMPACT_FULL) {
            char buf[256];

            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to open the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        if (hse_err_to_errno(err) != EEXIST && hse_err_to_errno(err) != EBUSY) {
            char buf[256];

            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to open the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }
    }

    /* If this process has opened the KVDB, open all KVSes too. */
    if (handle) {
        err = hse_kvdb_kvs_names_get(handle, &namec, &namev);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(
                stderr, "Failed to retrieve the KVS names of the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        for (size_t i = 0; i < namec; i++) {
            struct hse_kvs *k;

            err = hse_kvdb_kvs_open(handle, namev[i], kvs_paramc, kvs_paramv, &k);
            if (err) {
                char buf[256];
                hse_strerror(err, buf, sizeof(buf));
                fprintf(
                    stderr, "Failed to open the KVS (%s) within the KVDB (%s): %s\n", namev[i],
                    kvdb_home, buf);
                goto err_out;
            }
        }
    }

    err = pidfile_deserialize(kvdb_home, &content);
    if (err) {
        fprintf(
            stderr,
            "Failed to find the REST UNIX socket for the KVDB (%s). Ensure the KVDB is open in a "
            "process.\n",
            kvdb_home);
        goto err_out;
    }

    if (content.rest.socket_path[0] == '\0') {
        err = ENOENT;
        fprintf(stderr, "HSE socket is disabled in PID %d\n", content.pid);
        goto err_out;
    }

    err = rest_client_init(content.rest.socket_path);
    if (err) {
        fprintf(stderr, "Failed to initialize the rest client\n");
        goto err_out;
    }

    switch (request) {

    case REQ_COMPACT:
    case REQ_COMPACT_FULL:
        err = rest_kvdb_compact(content.alias, request == REQ_COMPACT_FULL);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Compaction request failed for the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        err = rest_kvdb_get_compaction_status(&status, content.alias);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Compaction request failed for the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        if (!status.kvcs_active) {
            printf("No active compaction request for KVDB (%s) in progress\n", kvdb_home);
            err = 0;
            goto err_out;
        }

        stop_ts = get_time_ns() + (timeout_sec * 1000ul * 1000ul * 1000ul);
        while (status.kvcs_active) {
            err = rest_kvdb_get_compaction_status(&status, content.alias);
            if (err) {
                char buf[256];
                hse_strerror(err, buf, sizeof(buf));
                fprintf(
                    stderr, "Compaction request failed for the KVDB (%s): %s\n", kvdb_home, buf);
                goto err_out;
            }

            if (status.kvcs_active)
                sleep(sleep_secs);

            if (get_time_ns() > stop_ts) {
                fprintf(stderr, "Compaction request timed out for the KVDB (%s)\n", kvdb_home);

                err = rest_kvdb_cancel_compaction(content.alias);
                if (err) {
                    char buf[256];
                    hse_strerror(err, buf, sizeof(buf));
                    fprintf(
                        stderr, "Failed to cancel compaction for the KVDB (%s): %s\n", kvdb_home,
                        buf);
                } else {
                    err = ETIMEDOUT;
                }

                goto err_out;
            }
        }

        printf(
            "Compaction request was %s for KVDB (%s)\n",
            status.kvcs_canceled ? "canceled" : "successful", kvdb_home);
        break;

    case REQ_CANCEL:
        err = rest_kvdb_cancel_compaction(content.alias);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to cancel compaction for the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        printf("Successfully canceled the compaction request for the KVDB (%s)\n", kvdb_home);
        break;

    case REQ_STATUS:
        err = rest_kvdb_get_compaction_status(&status, content.alias);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(
                stderr, "Failed to retrieve current compaction status of the KVDB (%s): %s\n",
                kvdb_home, buf);
            goto err_out;
        }

        printf(
            "samp_lwm: %.3lf\n"
            "samp_hwm: %.3lf\n"
            "samp_curr: %.3lf\n"
            "active: %s\n"
            "canceled: %s\n",
            status.kvcs_samp_lwm / 1000.0, status.kvcs_samp_hwm / 1000.0,
            status.kvcs_samp_curr / 1000.0, status.kvcs_active ? "true" : "false",
            status.kvcs_canceled ? "true" : "false");
        break;
    }

err_out:
    rest_client_fini();

    if (handle) {
        hse_kvdb_kvs_names_free(handle, namev);
        hse_kvdb_close(handle);
    }

    return hse_err_to_errno(err);
}
