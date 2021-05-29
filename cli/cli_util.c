/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>

#include <hse_util/rest_client.h>
#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/yaml.h>
#include <hse_util/rest_api.h>
#include <hse_util/timing.h>
#include <hse_util/parse_num.h>
#include <hse_util/param.h>
#include <hse_util/string.h>

#include <hse/hse.h>

static int
rest_kvs_list(struct yaml_context *yc, const char *kvdb)
{
    char      sock[PATH_MAX];
    char      url[PATH_MAX];
    char *    buf, *next;
    size_t    bufsz = (32 * 1024);
    char *    c;
    hse_err_t err;

    snprintf(url, sizeof(url), "mpool/%s", kvdb);

    snprintf(sock, sizeof(sock), "%s", getenv("HSE_REST_SOCK_PATH"));

    buf = calloc(1, bufsz);
    if (!buf)
        return -ENOMEM;

    err = merr_to_hse_err(curl_get(url, sock, buf, bufsz));
    if (err) {
        free(buf);
        return hse_err_to_errno(err);
    }

    next = buf;
    next[strlen(next) - 1] = '\0'; /* Get rid of the trailing newline char */

    c = strsep(&next, "\n"); /* Advance next past 'kvs_list:' */
    while (next) {
        char path[128];

        c = strsep(&next, "\n");
        while (*c != '-')
            c++;

        snprintf(path, sizeof(path), "%s/%s", kvdb, c + 2);
        yaml_element_list(yc, path);
    }

    yaml_end_element(yc);
    free(buf);

    return 0;
}

static int
rest_storage_stats_list(
    struct yaml_context          *yc,
    const char                   *kvdb,
    struct hse_kvdb_storage_info *info,
    char                         *cappath,
    char                         *stgpath,
    size_t                        pathlen)
{
    char      sock[PATH_MAX], url[PATH_MAX];
    char *    buf;
    size_t    bufsz = 32 * 1024;
    int       i;
    merr_t    err;

    struct {
        const char *key;
        u64        *val;
        char       *strval;
    } items[] = {
        { "total:", &info->total_bytes, NULL },
        { "available:", &info->available_bytes, NULL },
        { "allocated:", &info->allocated_bytes, NULL },
        { "used:", &info->used_bytes, NULL },
        { "capacity_path:", NULL, cappath },
        { "staging_path:", NULL, stgpath },
    };

    snprintf(url, sizeof(url), "mpool/%s/storage_stats", kvdb);
    snprintf(sock, sizeof(sock), "%s", getenv("HSE_REST_SOCK_PATH"));

    buf = calloc(1, bufsz);
    if (!buf)
        return ENOMEM;

    err = curl_get(url, sock, buf, bufsz);
    if (err) {
        free(buf);
        return merr_errno(err);
    }

    for (i = 0; i < NELEM(items); i++) {
        char *p, *end;
        u64   v;

        p = strstr(buf, items[i].key);
        if (!p) {
            free(buf);
            return EINVAL;
        }

        p += strlen(items[i].key);
        p += strspn(p, " ");

        if (items[i].val) {
            err = parse_u64_range(p, &end, 0, UINT64_MAX, &v);
            if (err) {
                free(buf);
                return merr_errno(err);
            }

            if (*end != '\0' && *end != '\n') {
                free(buf);
                return EINVAL;
            }

            *items[i].val = v;
        } else if (items[i].strval) {
            size_t len;

            end = p;

            while (*end != '\n' && *end != '\0')
                end++;

            if (end - buf + 1 > bufsz)
                return EINVAL;

            len = end - p;

            strlcpy(items[i].strval, p, pathlen);
            items[i].strval[len] = '\0';
        }
    }

    free(buf);

    return 0;
}

static void
space_to_string(u64 spc, char *buf, size_t bufsz)
{
    const char  suffixtab[] = "\0KMGTPEZY";
    double      space = spc;
    const char *stp;

    stp = suffixtab;
    while (space >= 1024) {
        space /= 1024;
        ++stp;
    }

    snprintf(buf, bufsz, "%4.2lf%c", space, *stp);
}

static void
emit_storage_info(
    struct yaml_context          *yc,
    struct hse_kvdb_storage_info *info,
    const char                   *cappath,
    const char                   *stgpath)
{
    char value[32];

    space_to_string(info->total_bytes, value, sizeof(value));
    yaml_element_field(yc, "total_space", value);
    snprintf(value, sizeof(value), "%lu", info->total_bytes);
    yaml_element_field(yc, "total_space_bytes", value);

    space_to_string(info->available_bytes, value, sizeof(value));
    yaml_element_field(yc, "avail_space", value);
    snprintf(value, sizeof(value), "%lu", info->available_bytes);
    yaml_element_field(yc, "avail_space_bytes", value);

    space_to_string(info->allocated_bytes, value, sizeof(value));
    yaml_element_field(yc, "allocated_space", value);
    snprintf(value, sizeof(value), "%lu", info->allocated_bytes);
    yaml_element_field(yc, "allocated_space_bytes", value);

    space_to_string(info->used_bytes, value, sizeof(value));
    yaml_element_field(yc, "used_space", value);
    snprintf(value, sizeof(value), "%lu", info->used_bytes);
    yaml_element_field(yc, "used_space_bytes", value);

    if (cappath && cappath[0] != '\0')
        yaml_element_field(yc, "capacity_path", cappath);
    if (stgpath && stgpath[0] != '\0')
        yaml_element_field(yc, "staging_path", stgpath);
}

static hse_err_t
kvdb_list_props(const char *kvdb, struct hse_params *params, struct yaml_context *yc)
{
    struct hse_kvdb              *hdl;
    struct hse_kvdb_storage_info  info = {};

    unsigned int kvs_cnt;
    char **      kvs_list;
    hse_err_t    err;
    char         path[129];
    int          i;

    err = hse_kvdb_open(kvdb, params, &hdl);
    if (err && hse_err_to_errno(err) != EBUSY && hse_err_to_errno(err) != ENODATA)
        return err;

    yaml_start_element_type(yc, "kvdb");
    yaml_start_element(yc, "name", kvdb);

    if (err) {
        char cappath[PATH_MAX], stgpath[PATH_MAX];

        err = rest_storage_stats_list(yc, kvdb, &info, cappath, stgpath, PATH_MAX);
        if (!err) {
            emit_storage_info(yc, &info, cappath, stgpath);

            yaml_start_element_type(yc, "kvslist");
            err = rest_kvs_list(yc, kvdb);
            yaml_end_element_type(yc);
        }
        goto exit;
    }

    err = hse_kvdb_storage_info_get(hdl, &info);
    if (err) {
        hse_kvdb_close(hdl);
        goto exit;
    }
    emit_storage_info(yc, &info, NULL, NULL);

    err = hse_kvdb_get_names(hdl, &kvs_cnt, &kvs_list);
    if (err) {
        hse_kvdb_close(hdl);
        goto exit;
    }

    yaml_start_element_type(yc, "kvslist");

    for (i = 0; i < kvs_cnt; i++) {
        snprintf(path, sizeof(path), "%s/%s", kvdb, kvs_list[i]);
        yaml_element_list(yc, path);
    }

    yaml_end_element(yc);
    yaml_end_element_type(yc); /* kvslist */

    hse_kvdb_free_names(hdl, kvs_list);
    hse_kvdb_close(hdl);

exit:
    yaml_end_element(yc);
    yaml_end_element_type(yc); /* kvdb */

    return err;
}

int
kvdb_list_print(
    const char *         kvdb,
    struct hse_params *  params,
    struct yaml_context *yc,
    bool                 verbose)
{
    hse_err_t err;
    int count = 0;

    err = kvdb_list_props(kvdb, params, yc);
    if (err) {
        char buf[256];

        if (hse_err_to_errno(err) == ENOENT)
            goto errout;

        hse_err_to_string(err, buf, sizeof(buf), NULL);
        yaml_field_fmt(yc, "error", "\"kvdb_list_props failed: %s\"", buf);
    }

    count = 1;

errout:
    hse_params_destroy(params);

    return count;
}

static hse_err_t
rest_kvdb_comp(const char *kvdb, const char *policy)
{
    char      sock[PATH_MAX];
    char      url[PATH_MAX];
    char *    buf;
    size_t    bufsz = (4 * 1024);
    hse_err_t err;

    snprintf(url, sizeof(url), "mpool/%s/compact/request?policy=%s", kvdb, policy);

    snprintf(sock, sizeof(sock), "%s", getenv("HSE_REST_SOCK_PATH"));

    buf = calloc(1, bufsz);
    if (!buf)
        return ENOMEM;

    err = merr_to_hse_err(curl_put(url, sock, 0, 0, buf, bufsz));
    free(buf);

    return err;
}

static hse_err_t
rest_kvdb_status(const char *kvdb, size_t bufsz, char *buf)
{
    char      sock[PATH_MAX];
    char      url[PATH_MAX];
    hse_err_t err;

    snprintf(url, sizeof(url), "mpool/%s/compact/status", kvdb);

    snprintf(sock, sizeof(sock), "%s", getenv("HSE_REST_SOCK_PATH"));

    err = merr_to_hse_err(curl_get(url, sock, buf, bufsz));
    if (err)
        return err;

    return 0UL;
}

static hse_err_t
rest_kvdb_params(const char *kvdb, size_t bufsz, char *buf)
{
    char      sock[PATH_MAX];
    char      url[PATH_MAX];
    hse_err_t err;

    snprintf(url, sizeof(url), "data/config/kvdb/%s", kvdb);

    snprintf(sock, sizeof(sock), "%s", getenv("HSE_REST_SOCK_PATH"));

    err = merr_to_hse_err(curl_get(url, sock, buf, bufsz));
    if (err)
        return err;

    return 0UL;
}

/**
 * rest_status_parse() - A simple parser for converting status from yaml
 *                       struct hse_kvdb_compact_status.
 * @buf:    input buffer containing yaml.
 * @status: output status struct.
 */
static int
rest_status_parse(const char *buf, struct hse_kvdb_compact_status *status)
{
    /* Example contents of 'buf':
     *
     *   status:
     *   samp_lwm_pct: 117
     *   samp_hwm_pct: 137
     *   samp_curr_pct: 1371
     *   request_active: 0
     */

    struct {
        const char *  name;
        unsigned int *value;
    } items[] = {
        { "samp_lwm_pct:", &status->kvcs_samp_lwm },
        { "samp_hwm_pct:", &status->kvcs_samp_hwm },
        { "samp_curr_pct:", &status->kvcs_samp_curr },
        { "request_active:", &status->kvcs_active },
        { "request_canceled:", &status->kvcs_canceled },
    };

    hse_err_t err;

    memset(status, 0, sizeof(*status));

    for (int i = 0; i < NELEM(items); i++) {

        const char *p;
        char *      end;
        size_t      n;
        u64         v;

        p = strstr(buf, items[i].name);

        if (!p)
            return -1;

        /* name should be at buf[0] or preceded by whitespace */
        if (p != buf && p[-1] != '\n')
            return -2;

        /* skip over white space after name */
        n = strlen(items[i].name);
        p += n;
        p += strspn(p, " ");

        /* parse an integer */
        err = merr_to_hse_err(parse_u64_range(p, &end, 0, UINT_MAX, &v));
        if (err)
            return -3;
        if (*end != '\0' && *end != '\n')
            return -4;

        *items[i].value = (unsigned int)v;
    }

    return 0;
}

/**
 * rest_params_print() - Print the KVDB params
 * @kvdb:  kvdb name
 * @buf:   input buffer containing yaml
 */
static void
rest_params_print(const char *kvdb, const char *buf)
{
    char        pfx[PATH_MAX], key[PATH_MAX];
    char        value[32];
    const char *p, *start;
    char *      pos;

    start = p = buf;

    snprintf(pfx, sizeof(pfx), "kvdb/%s/", kvdb);

    while (*p != '\0') {
        start = strstr(p, "path:");
        if (!start)
            return;

        start += strlen("path:");
        start += strspn(start, " ");
        start += strlen(pfx);

        p = start;

        while (*p != '\0' && *p != ' ' && *p != '\n')
            p++;

        snprintf(key, sizeof(key), "%.*s", (int)(p - start), start);
        pos = strchr(key, '/');
        if (pos) {
            *pos = '.';
            printf("kvs.%s", key);
        } else {
            printf("kvdb.%s", key);
        }

        if (*p != '\0') {
            start = strstr(p, "current:");
            if (!start)
                return;

            start += strlen("current:");
            start += strspn(start, " ");
            p = start;

            while (*p != '\0' && *p != '\n')
                p++;

            snprintf(value, sizeof(value), "%.*s", (int)(p - start), start);
            printf(": %s\n", value);
        }
    }
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
kvdb_compact_request(
    const char *       kvdb,
    struct hse_params *params,
    const char *       request_type,
    u32                timeout_sec)
{
    hse_err_t                      err;
    struct hse_kvdb *              handle = 0;
    struct hse_kvdb_compact_status status;

    char   stat_buf[256];
    u64    stop_ts;
    uint   sleep_secs = 2;
    char **kvs_list;
    uint   kvs_cnt;

    err = hse_kvdb_open(kvdb, params, &handle);
    if (err) {
        handle = 0;
        if (hse_err_to_errno(err) != EBUSY) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(stderr, "kvdb open %s failed: %s\n", kvdb, buf);
            goto err_out;
        }
    }

    /* If this process has opened the KVDB, open all KVSes too. */
    if (handle) {
        int i;

        err = hse_err_to_errno(hse_kvdb_get_names(handle, &kvs_cnt, &kvs_list));
        if (err) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(stderr, "unable to get %s kvs names: %s\n", kvdb, buf);
            goto err_out;
        }

        for (i = 0; i < kvs_cnt; i++) {
            struct hse_kvs *k;

            err = hse_kvdb_kvs_open(handle, kvs_list[i], 0, &k);
            if (err) {
                char buf[256];
                hse_err_to_string(err, buf, sizeof(buf), NULL);
                fprintf(stderr, "kvs open %s failed: %s\n", kvs_list[i], buf);
                goto err_out;
            }
        }
    }

    if (strcmp(request_type, "request") == 0) {

        const char *policy = "samp_lwm";

        printf("issuing compaction request with timeout of %u seconds\n", timeout_sec);

        err = rest_kvdb_comp(kvdb, policy);
        if (err) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(stderr, "rest_kvdb_comp(%s) failed: %s\n", policy, buf);
            goto err_out;
        }

        err = rest_kvdb_status(kvdb, sizeof(stat_buf), stat_buf);
        if (err) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(stderr, "rest_kvdb_status failed: %s\n", buf);
            goto err_out;
        }

        rest_status_parse(stat_buf, &status);

        if (!status.kvcs_active) {
            printf("no active compaction request in progress\n");
            err = 0;
            goto err_out;
        }

        stop_ts = get_time_ns() + (timeout_sec * 1000ul * 1000ul * 1000ul);
        while (status.kvcs_active) {

            err = rest_kvdb_status(kvdb, sizeof(stat_buf), stat_buf);
            if (err) {
                char buf[256];
                hse_err_to_string(err, buf, sizeof(buf), NULL);
                fprintf(stderr, "rest_kvdb_status failed: %s\n", buf);
                goto err_out;
            }

            rest_status_parse(stat_buf, &status);

            if (status.kvcs_active)
                sleep(sleep_secs);

            if (get_time_ns() > stop_ts) {

                fprintf(stderr, "compact kvdb %s timed out\n", kvdb);

                err = rest_kvdb_comp(kvdb, "cancel");
                if (err) {
                    char buf[256];
                    hse_err_to_string(err, buf, sizeof(buf), NULL);
                    fprintf(stderr, "rest_kvdb_comp cancel failed: %s\n", buf);
                } else {
                    err = ETIMEDOUT;
                }
                goto err_out;
            }
        }

        printf("compact kvdb %s %s\n", kvdb, status.kvcs_canceled ? "canceled" : "successful");

    } else if (strcmp(request_type, "cancel") == 0) {

        err = rest_kvdb_comp(kvdb, "cancel");
        if (err) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(stderr, "rest_kvdb_comp cancel failed: %s\n", buf);
            goto err_out;
        }

        printf("compact kvdb %s canceled\n", kvdb);

    } else if (strcmp(request_type, "status") == 0) {

        err = rest_kvdb_status(kvdb, sizeof(stat_buf), stat_buf);
        if (err) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(stderr, "rest_kvdb_status failed: %s\n", buf);
            goto err_out;
        }

        rest_status_parse(stat_buf, &status);

        rest_status_yaml(&status, stat_buf, sizeof(stat_buf));

        printf("%s", stat_buf);
    }

err_out:
    if (handle) {
        hse_kvdb_free_names(handle, kvs_list);
        hse_kvdb_close(handle);
    }

    hse_params_destroy(params);

    return hse_err_to_errno(err);
}

int
hse_kvdb_params(const char *kvdb, bool get)
{
    hse_err_t err = 0;
    char *    buf;
    size_t    bufsz = (32 * 1024);

    buf = calloc(1, bufsz);
    if (!buf)
        return -ENOMEM;

    if (get) {
        err = rest_kvdb_params(kvdb, bufsz, buf);
        if (err) {
            char buf[256];
            hse_err_to_string(err, buf, sizeof(buf), NULL);
            fprintf(
                stderr,
                "rest_kvdb_params failed: %s\n"
                "Ensure that KVDB '%s' is open in a process before querying its params.\n",
                buf,
                kvdb);
            goto err_out;
        }

        rest_params_print(kvdb, buf);
    }

err_out:
    free(buf);

    return hse_err_to_errno(err);
}
