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
#include <hse/test/mtf/framework.h>
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
struct hse_kvs *kvs;

void
mtf_get_global_params(size_t *const paramc, char ***const paramv)
{
    snprintf(socket_path, sizeof(socket_path), "/tmp/hse-kvs_rest_test-%d.sock", getpid());
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

    err = fxt_kvs_setup(kvdb, "kvs", 0, NULL, 0, NULL, &kvs);
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

    err = fxt_kvs_teardown(kvdb, "kvs", kvs);
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

MTF_BEGIN_UTEST_COLLECTION_PREPOST(kvs_rest_test, collection_pre, collection_post)

static merr_t
check_cn_tree_cb(
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

MTF_DEFINE_UTEST(kvs_rest_test, cn_tree)
{
    merr_t err;
    long status = REST_STATUS_BAD_REQUEST;
    const char *name = hse_kvs_name_get(kvs);
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    err = rest_client_fetch("GET", NULL, NULL, 0, check_cn_tree_cb, NULL,
        "/kvdbs/%s/kvs/%s/cn/tree", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/cn/tree?pretty=xyz", alias, name);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_params_cb(
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

MTF_DEFINE_UTEST(kvs_rest_test, params)
{
    merr_t err;
    const char *name = hse_kvs_name_get(kvs);
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);
    long status = REST_STATUS_METHOD_NOT_ALLOWED;

    err = rest_client_fetch("DELETE", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("PUT", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_params_cb, NULL, "/kvdbs/%s/kvs/%s/params",
        alias, name);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params?pretty=xyz", alias, name);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_param_cb(
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

MTF_DEFINE_UTEST(kvs_rest_test, params_specific)
{
    merr_t err;
    struct curl_slist *headers = NULL;
    const char *name = hse_kvs_name_get(kvs);
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);
    long status = REST_STATUS_METHOD_NOT_ALLOWED;

    headers = curl_slist_append(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE,
        REST_APPLICATION_JSON));
    ASSERT_NE(NULL, headers);

    err = rest_client_fetch("DELETE", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/transactions.enabled", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_param_cb, "false",
        "/kvdbs/%s/kvs/%s/params/transactions.enabled", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/does-not-exist", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("PUT", headers, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/cn_maint_disable", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params?pretty=xyz", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("PUT", NULL, "true", 4, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/cn_maint_disable", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_LOCKED;
    err = rest_client_fetch("PUT", headers, "true", 4, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/transactions.enabled", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_CREATED;
    err = rest_client_fetch("PUT", headers, "true", 4, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/params/cn_maint_disable", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_param_cb, "true",
        "/kvdbs/%s/kvs/%s/params/cn_maint_disable", alias, name);
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

MTF_DEFINE_UTEST(kvs_rest_test, perfc)
{
    merr_t err;
    char long_path[DT_PATH_MAX + 1];
    long status = REST_STATUS_BAD_REQUEST;
    const char *name = hse_kvs_name_get(kvs);
    const char *alias = ikvdb_alias((struct ikvdb *)kvdb);

    memset(long_path, 'a', sizeof(long_path));
    long_path[DT_PATH_MAX] = '\0';

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/perfc/%s", alias, name, long_path);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/perfc?pretty=xyz", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/perfc?blkids=xyz", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status,
        "/kvdbs/%s/kvs/%s/perfc/does-not-exist", alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_perfc_cb, NULL, "/kvdbs/%s/kvs/%s/perfc",
        alias, name);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_perfc_cb, NULL,
        "/kvdbs/%s/kvs/%s/perfc/CNCOMP/spill", alias, name);
    ASSERT_EQ(0, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(kvs_rest_test)
