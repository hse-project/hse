/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>

#include <hse/hse.h>
#include <mtf/framework.h>
#include <hse/cli/rest/client.h>
#include <hse/error/merr.h>
#include <hse/rest/headers.h>
#include <hse/rest/status.h>
#include <hse/test/fixtures/kvdb.h>
#include <hse/test/fixtures/kvs.h>

#include <hse/ikvdb/ikvdb.h>
#include <hse/util/base.h>
#include <hse/mpool/mpool.h>

char socket_path[PATH_MAX];
char rest_socket_path_param[PATH_MAX + PATH_MAX / 2];
char *gparams[2];

struct hse_kvdb *kvdb;
struct hse_kvs *kvs1, *kvs2;

void
mtf_get_global_params(size_t *const paramc, char ***const paramv)
{
    snprintf(socket_path, sizeof(socket_path), "/tmp/hse-kvdb_rest_test-%d.sock", getpid());
    snprintf(rest_socket_path_param, sizeof(rest_socket_path_param), "rest.socket_path=%s",
        socket_path);

    gparams[0] = "rest.enabled=true";
    gparams[1] = rest_socket_path_param;

    *paramc = NELEM(gparams);
    *paramv = gparams;
}

static int
collection_pre(struct mtf_test_info *const lcl_ti)
{
    merr_t err;

    err = fxt_kvdb_setup(mtf_kvdb_home, 0, NULL, 0, NULL, &kvdb);
    if (err)
        goto out;

    err = fxt_kvs_setup(kvdb, "kvs1", 0, NULL, 0, NULL, &kvs1);
    if (err)
        goto out;

    err = fxt_kvs_setup(kvdb, "kvs2", 0, NULL, 0, NULL, &kvs2);
    if (err)
        goto out;

    err = rest_client_init(socket_path);

out:
    if (err && kvdb)
        fxt_kvdb_teardown(mtf_kvdb_home, kvdb);

    return merr_errno(err);
}

static int
collection_post(struct mtf_test_info *const lcl_ti)
{
    merr_t err;

    rest_client_fini();

    err = fxt_kvs_teardown(kvdb, "kvs1", kvs1);
    if (err)
        goto out;

    err = fxt_kvs_teardown(kvdb, "kvs2", kvs2);
    if (err)
        goto out;

    err = fxt_kvdb_teardown(mtf_kvdb_home, kvdb);
    if (err)
        goto out;

out:
    return merr_errno(err);
}

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
check_status_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    const long *needed = arg;

    return *needed == status ? 0 : status_to_error(status);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvdb_rest_test, collection_pre, collection_post)

static merr_t
check_compaction_status_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body, *samp_lwm_pct, *samp_hwm_pct, *samp_curr_pct, *active, *canceled;

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EINVAL);
        } else {
            return merr(ENOMEM);
        }
    }

    samp_lwm_pct = cJSON_GetObjectItemCaseSensitive(body, "samp_lwm_pct");
    samp_hwm_pct = cJSON_GetObjectItemCaseSensitive(body, "samp_hwm_pct");
    samp_curr_pct = cJSON_GetObjectItemCaseSensitive(body, "samp_curr_pct");
    active = cJSON_GetObjectItemCaseSensitive(body, "active");
    canceled = cJSON_GetObjectItemCaseSensitive(body, "canceled");

    if (!cJSON_IsNumber(samp_lwm_pct) || cJSON_GetNumberValue(samp_lwm_pct) != 1178) {
        err = merr(EINVAL);
        goto out;
    }

    if (!cJSON_IsNumber(samp_hwm_pct) || cJSON_GetNumberValue(samp_hwm_pct) != 1375) {
        err = merr(EINVAL);
        goto out;
    }

    if (!cJSON_IsNumber(samp_curr_pct) || cJSON_GetNumberValue(samp_curr_pct) != 1000) {
        err = merr(EINVAL);
        goto out;
    }

    if (!cJSON_IsBool(active) || cJSON_IsTrue(active)) {
        err = merr(EINVAL);
        goto out;
    }

    if (!cJSON_IsBool(canceled) || cJSON_IsTrue(canceled)) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, compact)
{
    merr_t err;
    long status = REST_STATUS_OK;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_compaction_status_cb, NULL,
        "/kvdbs/%s/compact", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_ACCEPTED;
    err = rest_client_fetch("POST", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/compact", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_ACCEPTED;
    err = rest_client_fetch("DELETE", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/compact", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/compact?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_csched_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body = NULL;

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsArray(body)) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, csched)
{
    merr_t err;
    long status = REST_STATUS_OK;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_csched_cb, NULL,
        "/kvdbs/%s/csched", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/csched?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_home_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body;

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsString(body)) {
        err = merr(EINVAL);
        goto out;
    }

    if (strcmp(cJSON_GetStringValue(body), mtf_kvdb_home))
        return merr(EINVAL);

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, home)
{
    merr_t err;
    long status = REST_STATUS_BAD_REQUEST;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_home_cb, NULL, "/kvdbs/%s/home",
        alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/home?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_kvs_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body;
    bool found[2] = { 0 }; /* 2 KVS to check for */

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsArray(body)) {
        err = merr(EINVAL);
        goto out;
    }

    if (cJSON_GetArraySize(body) != 2) {
        err = merr(EINVAL);
        goto out;
    }

    for (int i = 0; i < cJSON_GetArraySize(body); i++) {
        cJSON *elem = cJSON_GetArrayItem(body, i);
        if (!cJSON_IsString(elem)) {
            err = merr(EINVAL);
            goto out;
        }

        if (strcmp(cJSON_GetStringValue(elem), hse_kvs_name_get(kvs1)) == 0) {
            if (found[0]) {
                err = merr(EINVAL);
                goto out;
            }

            found[0] = true;
            continue;
        }

        if (strcmp(cJSON_GetStringValue(elem), hse_kvs_name_get(kvs2)) == 0) {
            if (found[1]) {
                err = merr(EINVAL);
                goto out;
            }

            found[1] = true;
            continue;
        }
    }

    if (!found[0] || !found[1]) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, kvs)
{
    merr_t err;
    long status = REST_STATUS_BAD_REQUEST;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_kvs_cb, NULL, "/kvdbs/%s/kvs",
        alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_mclass_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body;
    bool found[HSE_MCLASS_COUNT] = { 0 };

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsArray(body)) {
        err = merr(EINVAL);
        goto out;
    }

    if (cJSON_GetArraySize(body) > HSE_MCLASS_COUNT) {
        err = merr(EINVAL);
        goto out;
    }

    for (int i = 0; i < cJSON_GetArraySize(body); i++) {
        cJSON *elem = cJSON_GetArrayItem(body, i);
        if (!cJSON_IsString(elem)) {
            err = merr(EINVAL);
            goto out;
        }

        if (strcmp(cJSON_GetStringValue(elem), HSE_MCLASS_CAPACITY_NAME) == 0) {
            if (found[HSE_MCLASS_CAPACITY]) {
                err = merr(EINVAL);
                goto out;
            }

            found[HSE_MCLASS_CAPACITY] = true;
            continue;
        }

        if (strcmp(cJSON_GetStringValue(elem), HSE_MCLASS_STAGING_NAME) == 0) {
            if (found[HSE_MCLASS_STAGING]) {
                err = merr(EINVAL);
                goto out;
            }

            found[HSE_MCLASS_STAGING] = true;
            continue;
        }

        if (strcmp(cJSON_GetStringValue(elem), HSE_MCLASS_PMEM_NAME) == 0) {
            if (found[HSE_MCLASS_PMEM]) {
                err = merr(EINVAL);
                goto out;
            }

            found[HSE_MCLASS_PMEM] = true;
            continue;
        }
    }

    if (!found[HSE_MCLASS_CAPACITY] || found[HSE_MCLASS_STAGING] || found[HSE_MCLASS_PMEM]) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, mclass)
{
    merr_t err;
    long status = REST_STATUS_BAD_REQUEST;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_mclass_cb, NULL, "/kvdbs/%s/mclass", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/mclass?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_specific_mclass_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    struct hse_mclass_info info;
    cJSON *body, *path, *allocated_bytes, *used_bytes;
    struct mpool *mp = ikvdb_mpool_get((struct ikvdb *)kvdb);

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    err = mpool_mclass_info_get(mp, HSE_MCLASS_CAPACITY, &info);
    if (err)
        return err;

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsObject(body)) {
        err = merr(EINVAL);
        goto out;
    }

    path = cJSON_GetObjectItemCaseSensitive(body, "path");
    allocated_bytes = cJSON_GetObjectItemCaseSensitive(body, "allocated_bytes");
    used_bytes = cJSON_GetObjectItemCaseSensitive(body, "used_bytes");

    if (!cJSON_IsString(path)) {
        err = merr(EINVAL);
        goto out;
    }

    if (!cJSON_IsNumber(allocated_bytes)) {
        err = merr(EINVAL);
        goto out;
    }

    if (!cJSON_IsNumber(used_bytes)) {
        err = merr(EINVAL);
        goto out;
    }

    if (strcmp(cJSON_GetStringValue(path), info.mi_path)) {
        err = merr(EINVAL);
        goto out;
    }

    if (cJSON_GetNumberValue(allocated_bytes) != info.mi_allocated_bytes) {
        err = merr(EINVAL);
        goto out;
    }

    if (cJSON_GetNumberValue(used_bytes) != info.mi_used_bytes) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, mclass_specific)
{
    merr_t err;
    long status = REST_STATUS_NOT_FOUND;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/mclass/" HSE_MCLASS_STAGING_NAME,
        alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/mclass/" HSE_MCLASS_PMEM_NAME,
        alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_specific_mclass_cb,
        HSE_MCLASS_CAPACITY_NAME, "/kvdbs/%s/mclass/" HSE_MCLASS_CAPACITY_NAME,
        alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/mclass/" HSE_MCLASS_CAPACITY_NAME "?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
params_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body;

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsObject(body)) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, params)
{
    merr_t err;
    long status = REST_STATUS_METHOD_NOT_ALLOWED;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("DELETE", NULL, NULL, 0, check_status_cb, &status, "/kvdbs/%s/params",
        alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("PUT", NULL, NULL, 0, check_status_cb, &status, "/kvdbs/%s/params",
        alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, params_cb, NULL, "/kvdbs/%s/params",
        alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/params?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
read_csched_leaf_pct(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    if (strncmp(output, arg, output_len) != 0)
        return merr(EINVAL);

    return 0;
}

MTF_DEFINE_UTEST(kvdb_rest_test, params_specific)
{
    merr_t err;
    struct curl_slist *headers = NULL;
    long status = REST_STATUS_METHOD_NOT_ALLOWED;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    headers = curl_slist_append(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE,
        REST_APPLICATION_JSON));
    ASSERT_NE(NULL, headers);

    err = rest_client_fetch("DELETE", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/params/csched_leaf_pct", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, read_csched_leaf_pct, "90",
        "/kvdbs/%s/params/csched_leaf_pct", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/params/does-not-exist",
        alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("PUT", headers, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/params/csched_leaf_pct", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("PUT", NULL, "91", 1, check_status_cb, &status,
        "/kvdbs/%s/params/csched_leaf_pct", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/params/csched_leaf_pct?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_CREATED;
    err = rest_client_fetch("PUT", headers, "91", 1, check_status_cb, &status,
        "/kvdbs/%s/params/csched_leaf_pct", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, read_csched_leaf_pct, "91",
        "/kvdbs/%s/params/csched_leaf_pct", alias);
    ASSERT_EQ(0, merr_errno(err));

    curl_slist_free_all(headers);
}

static merr_t
check_perfc_cb(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    merr_t err = 0;
    cJSON *body = NULL;

    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    body = cJSON_ParseWithLength(output, output_len);
    if (!body) {
        if (cJSON_GetErrorPtr()) {
            return merr(EPROTO);
        } else {
            return merr(ENOMEM);
        }
    }

    if (!cJSON_IsArray(body)) {
        err = merr(EINVAL);
        goto out;
    }

out:
    cJSON_Delete(body);

    return err;
}

MTF_DEFINE_UTEST(kvdb_rest_test, perfc)
{
    merr_t err;
    char long_path[DT_PATH_MAX + 1];
    long status = REST_STATUS_BAD_REQUEST;
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    memset(long_path, 'a', sizeof(long_path));
    long_path[DT_PATH_MAX] = '\0';

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/kvdbs/%s/perfc/%s",
        alias, long_path);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/perfc?pretty=xyz", alias);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/perfc/does-not-exist", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_perfc_cb, NULL, "/kvdbs/%s/perfc", alias);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_perfc_cb, NULL,
        "/kvdbs/%s/perfc/C0SKOP/set", alias);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(kvdb_rest_test)
