/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>

#include <hse/cli/rest/api.h>
#include <hse/cli/rest/client.h>
#include <hse/error/merr.h>
#include <hse_util/inttypes.h>
#include <hse_util/yaml.h>
#include <hse_util/arch.h>
#include <hse_util/parse_num.h>

#include <hse/hse.h>
#include <hse/experimental.h>

#include <hse/pidfile/pidfile.h>

#include <bsd/string.h>

static hse_err_t
kvdb_info_props(
    const char          *kvdb_home,
    const size_t         paramc,
    const char *const   *paramv,
    struct yaml_context *yc)
{
    struct hse_kvdb *hdl;
    size_t           kvs_cnt;
    char **          kvs_list;
    hse_err_t        err;
    int              i;
    struct pidfile   content;
    bool used_rest = false;

    err = hse_kvdb_open(kvdb_home, paramc, paramv, &hdl);
    if (err && hse_err_to_errno(err) != EEXIST && hse_err_to_errno(err) != ENODATA &&
        hse_err_to_errno(err) != EBUSY)
        return err;

    yaml_start_element_type(yc, "kvdb");
    yaml_start_element(yc, "home", kvdb_home);

    if (err) {
        err = pidfile_deserialize(kvdb_home, &content);
        if (err) {
            fprintf(
                stderr,
                "Failed to find the UNIX socket for the KVDB (%s). Ensure the KVDB is open in a "
                "process.\n",
                kvdb_home);
            goto exit;
        }

        if (content.socket.path[0] == '\0') {
            err = ENOENT;
            fprintf(stderr, "HSE socket is disabled in PID %d\n", content.pid);
            goto exit;
        }

        err = rest_client_init(content.socket.path);
        if (err) {
            fprintf(stderr, "Failed to initialize the rest client\n");
            goto exit;
        }

        err = rest_kvdb_get_kvs_names(&kvs_cnt, &kvs_list, content.alias);
        if (err)
            goto exit;

        used_rest = true;
    } else {
        err = hse_kvdb_kvs_names_get(hdl, &kvs_cnt, &kvs_list);
        if (err) {
            hse_kvdb_close(hdl);
            goto exit;
        }
    }

    yaml_start_element_type(yc, "kvslist");

    for (i = 0; i < kvs_cnt; i++)
        yaml_element_list(yc, kvs_list[i]);

    yaml_end_element(yc);
    yaml_end_element_type(yc); /* kvslist */

    if (!used_rest) {
        hse_kvdb_kvs_names_free(hdl, kvs_list);
    } else {
        rest_kvdb_free_kvs_names(kvs_list);
    }

    hse_kvdb_close(hdl);

exit:
    yaml_end_element(yc);
    yaml_end_element_type(yc); /* kvdb */

    if (used_rest)
        rest_client_fini();

    return err;
}

bool
kvdb_info_print(
    const char *         kvdb_home,
    const size_t         paramc,
    const char *const *  paramv,
    struct yaml_context *yc)
{
    hse_err_t err;

    err = kvdb_info_props(kvdb_home, paramc, paramv, yc);
    if (err) {
        char buf[256];

        if (hse_err_to_errno(err) == ENOENT)
            return false;

        hse_strerror(err, buf, sizeof(buf));
        yaml_field_fmt(yc, "error", "\"kvdb_info_props failed: %s\"", buf);
    }

    return true;
}

static void
rest_status_yaml(struct hse_kvdb_compact_status *status, char *buf, size_t bufsz)
{
    struct yaml_context yc = {
        .yaml_indent = 0,
        .yaml_offset = 0,
        .yaml_buf = buf,
        .yaml_buf_sz = bufsz,
        .yaml_emit = NULL,
    };

    uint lwm = status->kvcs_samp_lwm;
    uint hwm = status->kvcs_samp_hwm;
    uint cur = status->kvcs_samp_curr;

    yaml_start_element_type(&yc, "compact_status");

    yaml_field_fmt(&yc, "samp_lwm", "%u.%02u", lwm / 100, lwm % 100);
    yaml_field_fmt(&yc, "samp_hwm", "%u.%02u", hwm / 100, hwm % 100);
    yaml_field_fmt(&yc, "samp_curr", "%u.%02u", cur / 100, cur % 100);
    yaml_field_fmt(&yc, "request_active", "%u", status->kvcs_active);
    yaml_field_fmt(&yc, "request_canceled", "%u", status->kvcs_canceled);

    yaml_end_element(&yc);
    yaml_end_element_type(&yc);
}

int
kvdb_compact_request(const char *kvdb_home, const char *request_type, u32 timeout_sec)
{
    hse_err_t                      err;
    struct hse_kvdb *              handle = 0;
    struct hse_kvdb_compact_status status;
    struct pidfile                 content;

    char   stat_buf[256];
    u64    stop_ts;
    uint   sleep_secs = 2;
    char **kvs_list;
    size_t kvs_cnt;

    err = hse_kvdb_open(kvdb_home, 0, NULL, &handle);
    if (err) {
        handle = 0;
        if (hse_err_to_errno(err) != EEXIST && hse_err_to_errno(err) != EBUSY) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to open the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }
    }

    /* If this process has opened the KVDB, open all KVSes too. */
    if (handle) {
        int i;

        err = hse_err_to_errno(hse_kvdb_kvs_names_get(handle, &kvs_cnt, &kvs_list));
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to retrieve the KVS names of the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        for (i = 0; i < kvs_cnt; i++) {
            struct hse_kvs *k;

            err = hse_kvdb_kvs_open(handle, kvs_list[i], 0, NULL, &k);
            if (err) {
                char buf[256];
                hse_strerror(err, buf, sizeof(buf));
                fprintf(stderr, "Failed to open the KVS (%s) within the KVDB (%s): %s\n", kvs_list[i], kvdb_home, buf);
                goto err_out;
            }
        }
    }

    err = pidfile_deserialize(kvdb_home, &content);
    if (err) {
        fprintf(
            stderr,
            "Failed to find the UNIX socket for the KVDB (%s). Ensure the KVDB is open in a "
            "process.\n",
            kvdb_home);
        goto err_out;
    }

    if (content.socket.path[0] == '\0') {
        err = ENOENT;
        fprintf(stderr, "HSE socket is disabled in PID %d\n", content.pid);
        goto err_out;
    }

    err = rest_client_init(content.socket.path);
    if (err) {
        fprintf(stderr, "Failed to initialize the rest client\n");
        goto err_out;
    }

    if (strcmp(request_type, "request") == 0) {
        err = rest_kvdb_compact(content.alias);
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
                fprintf(stderr, "Compaction request failed for the KVDB (%s): %s\n", kvdb_home, buf);
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
                    fprintf(stderr, "Failed to cancel compaction for the KVDB (%s): %s\n", kvdb_home, buf);
                } else {
                    err = ETIMEDOUT;
                }

                goto err_out;
            }
        }

        printf("Compaction request was %s for KVDB (%s)\n", status.kvcs_canceled ? "canceled" : "successful", kvdb_home);
    } else if (strcmp(request_type, "cancel") == 0) {
        err = rest_kvdb_cancel_compaction(content.alias);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to cancel compaction for the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        printf("Successfully canceled the compaction request for the KVDB (%s)\n", kvdb_home);
    } else if (strcmp(request_type, "status") == 0) {
        err = rest_kvdb_get_compaction_status(&status, content.alias);
        if (err) {
            char buf[256];
            hse_strerror(err, buf, sizeof(buf));
            fprintf(stderr, "Failed to retrieve current compaction status of the KVDB (%s): %s\n", kvdb_home, buf);
            goto err_out;
        }

        rest_status_yaml(&status, stat_buf, sizeof(stat_buf));

        printf("%s", stat_buf);
    }

err_out:
    rest_client_fini();

    if (handle) {
        hse_kvdb_kvs_names_free(handle, kvs_list);
        hse_kvdb_close(handle);
    }

    return hse_err_to_errno(err);
}
