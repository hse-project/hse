/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>
#include <curl/curl.h>

#include <hse/experimental.h>
#include <hse/hse.h>
#include <hse/limits.h>
#include <hse/types.h>

#include <hse/cli/rest/api.h>
#include <hse/cli/rest/client.h>
#include <hse/error/merr.h>
#include <hse/rest/headers.h>
#include <hse/rest/params.h>
#include <hse/rest/status.h>

#define QUERY_VALUE_FROM_BOOL(b) ((b) ? "true" : "false")

static merr_t
status_to_error(const long status)
{
    if (status == REST_STATUS_NOT_FOUND) {
        return merr(ENOENT);
    } else if (status >= REST_STATUS_BAD_REQUEST) {
        return merr(EBADMSG);
    }

    return 0;
}

static merr_t
copy_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    merr_t err;
    const char **out = arg;

    err = status_to_error(status);
    if (err)
        return err;

    *out = strdup(output);
    if (!*out)
        return merr(ENOMEM);

    return 0;
}

static merr_t
check_status_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    const long *needed = arg;

    return *needed == status ? 0 : status_to_error(status);
}

merr_t
rest_get_param(char ** const value, const char * const param, bool pretty)
{
    if (!param || !value)
        return merr(EINVAL);

    *value = NULL;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, copy_cb, value, "/params/%s?pretty=%s", param,
        QUERY_VALUE_FROM_BOOL(pretty));
}

merr_t
rest_get_params(char ** const config, const bool pretty)
{
    if (!config)
        return merr(EINVAL);

    *config = NULL;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, copy_cb, config, "/params?pretty=%s", QUERY_VALUE_FROM_BOOL(pretty));
}

merr_t
rest_set_param(const char * const param, const char * const value)
{
    struct curl_slist *headers = NULL;
    long status = REST_STATUS_CREATED;

    if (!param || !value)
        return merr(EINVAL);

    headers = curl_slist_append(
        headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON));
    if (!headers)
        return merr(ENOMEM);

    return rest_client_fetch(
        "PUT", headers, value, strlen(value), check_status_cb, &status, "/params/%s", param);
}

merr_t
rest_kvdb_cancel_compaction(const char * const alias)
{
    long status = REST_STATUS_ACCEPTED;

    if (!alias)
        return merr(EINVAL);

    return rest_client_fetch(
        "DELETE", NULL, NULL, 0, check_status_cb, &status, "/kvdbs/%s/compact", alias);
}

merr_t
rest_kvdb_compact(const char * const alias, bool full)
{
    long status = REST_STATUS_ACCEPTED;
    const char *fmt = "/kvdbs/%s/compact?full=%s";

    if (!alias)
        return merr(EINVAL);

    return rest_client_fetch(
        "POST", NULL, NULL, 0, check_status_cb, &status, fmt, alias, QUERY_VALUE_FROM_BOOL(full));
}

void
rest_kvdb_free_kvs_names(char ** const namev)
{
    free(namev);
}

static merr_t
kvdb_get_compaction_status_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    merr_t err;
    cJSON *body, *samp_lwm_pct, *samp_hwm_pct, *samp_curr_pct, *active, *canceled;
    struct hse_kvdb_compact_status *comp_status = arg;

    err = status_to_error(status);
    if (err)
        return err;

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }
    assert(cJSON_IsObject(body));

    samp_lwm_pct = cJSON_GetObjectItemCaseSensitive(body, "samp_lwm_pct");
    samp_hwm_pct = cJSON_GetObjectItemCaseSensitive(body, "samp_hwm_pct");
    samp_curr_pct = cJSON_GetObjectItemCaseSensitive(body, "samp_curr_pct");
    active = cJSON_GetObjectItemCaseSensitive(body, "active");
    canceled = cJSON_GetObjectItemCaseSensitive(body, "canceled");

    assert(cJSON_IsNumber(samp_lwm_pct));
    assert(cJSON_IsNumber(samp_hwm_pct));
    assert(cJSON_IsNumber(samp_curr_pct));
    assert(cJSON_IsBool(active));
    assert(cJSON_IsBool(canceled));

    comp_status->kvcs_samp_lwm = (unsigned int)cJSON_GetNumberValue(samp_lwm_pct);
    comp_status->kvcs_samp_hwm = (unsigned int)cJSON_GetNumberValue(samp_hwm_pct);
    comp_status->kvcs_samp_curr = (unsigned int)cJSON_GetNumberValue(samp_curr_pct);
    comp_status->kvcs_active = (unsigned int)cJSON_IsTrue(active);
    comp_status->kvcs_canceled = (unsigned int)cJSON_IsTrue(canceled);

    cJSON_Delete(body);

    return 0;
}

merr_t
rest_kvdb_get_compaction_status(
    struct hse_kvdb_compact_status * const status,
    const char * const alias)
{

    if (!alias)
        return merr(EINVAL);

    return rest_client_fetch(
        "GET", NULL, NULL, 0, kvdb_get_compaction_status_cb, status, "/kvdbs/%s/compact", alias);
}

static merr_t
kvdb_get_configured_mclasses_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    int len;
    merr_t err;
    cJSON *body;
    bool *configured = arg;

    err = status_to_error(status);
    if (err)
        return err;

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }
    assert(cJSON_IsArray(body));

    len = cJSON_GetArraySize(body);
    for (int i = 0; i < len; i++) {
        cJSON *elem = cJSON_GetArrayItem(body, i);
        const char *mclass = cJSON_GetStringValue(elem);

        assert(cJSON_IsString(elem));

        for (enum hse_mclass j = HSE_MCLASS_BASE; j < HSE_MCLASS_COUNT; j++) {
            if (strcmp(mclass, hse_mclass_name_get(j)) == 0) {
                configured[j] = true;
                break;
            }
        }
    }

    cJSON_Delete(body);

    return 0;
}

merr_t
rest_kvdb_get_configured_mclasses(
    bool configured[static HSE_MCLASS_COUNT],
    const char * const alias)
{
    if (!alias || !configured)
        return merr(EINVAL);

    memset(configured, 0, HSE_MCLASS_COUNT * sizeof(*configured));

    return rest_client_fetch(
        "GET", NULL, NULL, 0, kvdb_get_configured_mclasses_cb, configured, "/kvdbs/%s/mclass",
        alias);
}

merr_t
rest_kvdb_get_home(char ** const home, const char * const alias)
{
    if (!alias || !home)
        return merr(EINVAL);

    return rest_client_fetch("GET", NULL, NULL, 0, copy_cb, home, "/kvdbs/%s/home", alias);
}

struct kvdb_get_kvs_names_arg {
    size_t *namec;
    char ***namev;
};

static merr_t
kvdb_get_kvs_names_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    size_t len;
    merr_t err;
    char *name;
    cJSON *body;
    char **namev = NULL;
    const struct kvdb_get_kvs_names_arg *inputs = arg;

    err = status_to_error(status);
    if (err)
        return err;

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }

    assert(cJSON_IsArray(body));

    len = (size_t)cJSON_GetArraySize(body);
    namev = calloc(len, sizeof(*namev) + HSE_KVS_NAME_LEN_MAX);
    if (!namev) {
        err = merr(ENOMEM);
        goto out;
    }

    /* Seek to start of the section holding the strings */
    name = (char *)(namev + len);
    for (int i = 0; i < len; i++) {
        cJSON *elem;

        elem = cJSON_GetArrayItem(body, i);
        assert(cJSON_IsString(elem));

        strlcpy(name, cJSON_GetStringValue(elem), HSE_KVS_NAME_LEN_MAX);
        namev[i] = name;
        name += HSE_KVS_NAME_LEN_MAX;
    }

    *inputs->namec = len;
    *inputs->namev = namev;

out:
    if (err)
        free(namev);

    cJSON_Delete(body);

    return err;
}

merr_t
rest_kvdb_get_kvs_names(size_t * const namec, char *** const namev, const char * const alias)
{
    struct kvdb_get_kvs_names_arg arg;

    arg.namec = namec;
    arg.namev = namev;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, kvdb_get_kvs_names_cb, &arg, "/kvdbs/%s/kvs", alias);
}

static merr_t
kvdb_get_mclass_info_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    merr_t err;
    cJSON *body, *path, *used_bytes, *allocated_bytes;
    struct hse_mclass_info *info = arg;

    err = status_to_error(status);
    if (err)
        return err;

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }
    assert(cJSON_IsObject(body));

    path = cJSON_GetObjectItemCaseSensitive(body, "path");
    used_bytes = cJSON_GetObjectItemCaseSensitive(body, "used_bytes");
    allocated_bytes = cJSON_GetObjectItemCaseSensitive(body, "allocated_bytes");

    assert(cJSON_IsString(path));
    assert(cJSON_IsNumber(used_bytes));
    assert(cJSON_IsNumber(allocated_bytes));

    info->mi_allocated_bytes = (uint64_t)cJSON_GetNumberValue(allocated_bytes);
    info->mi_used_bytes = (uint64_t)cJSON_GetNumberValue(used_bytes);
    strlcpy(info->mi_path, cJSON_GetStringValue(path), sizeof(info->mi_path));

    cJSON_Delete(body);

    return 0;
}

merr_t
rest_kvdb_get_mclass_info(
    struct hse_mclass_info * const info,
    const char * const alias,
    const enum hse_mclass mclass)
{
    if (!alias || !info)
        return merr(EINVAL);

    memset(info, 0, sizeof(*info));

    return rest_client_fetch(
        "GET", NULL, NULL, 0, kvdb_get_mclass_info_cb, info, "/kvdbs/%s/mclass/%s", alias,
        hse_mclass_name_get(mclass));
}

merr_t
rest_kvdb_get_param(
    char ** const value,
    const char * const alias,
    const char * const param,
    const bool pretty)
{
    if (!alias || !param || !value)
        return merr(EINVAL);

    *value = NULL;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, copy_cb, value, "/kvdbs/%s/params/%s?pretty=%s", alias, param,
        QUERY_VALUE_FROM_BOOL(pretty));
}

merr_t
rest_kvdb_get_params(char ** const config, const char * const alias, const bool pretty)
{
    if (!alias || !config)
        return merr(EINVAL);

    *config = NULL;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, copy_cb, config, "/kvdbs/%s/params?pretty=%s", alias,
        QUERY_VALUE_FROM_BOOL(pretty));
}

merr_t
rest_kvdb_set_param(const char * const alias, const char * const param, const char * const value)
{
    struct curl_slist *headers = NULL;
    long status = REST_STATUS_CREATED;

    if (!alias || !param || !value)
        return merr(EINVAL);

    headers = curl_slist_append(
        headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON));
    if (!headers)
        return merr(ENOMEM);

    return rest_client_fetch(
        "PUT", headers, value, strlen(value), check_status_cb, &status, "/kvdbs/%s/params/%s",
        alias, param);
}

merr_t
rest_kvs_get_param(
    char ** const value,
    const char * const alias,
    const char * const name,
    const char * const param,
    const bool pretty)
{
    if (!alias || !name || !param || !value)
        return merr(EINVAL);

    *value = NULL;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, copy_cb, value, "/kvdbs/%s/kvs/%s/params/%s?pretty=%s", alias, name,
        param, QUERY_VALUE_FROM_BOOL(pretty));
}

merr_t
rest_kvs_get_params(
    const char * const alias,
    const char * const name,
    const bool pretty,
    char ** const config)
{
    if (!alias || !name || !config)
        return merr(EINVAL);

    *config = NULL;

    return rest_client_fetch(
        "GET", NULL, NULL, 0, copy_cb, config, "/kvdbs/%s/kvs/%s/params?pretty=%s", alias, name,
        QUERY_VALUE_FROM_BOOL(pretty));
}

merr_t
rest_kvs_set_param(
    const char * const alias,
    const char * const name,
    const char * const param,
    const char * const value)
{
    struct curl_slist *headers = NULL;
    long status = REST_STATUS_CREATED;

    if (!alias || !name || !param || !value)
        return merr(EINVAL);

    headers = curl_slist_append(
        headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON));
    if (!headers)
        return merr(ENOMEM);

    return rest_client_fetch(
        "PUT", headers, value, strlen(value), check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/%s", alias, name, param);
}
