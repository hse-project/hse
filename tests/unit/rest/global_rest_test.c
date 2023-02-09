/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <cjson/cJSON.h>
#include <curl/curl.h>

#include <hse/cli/rest/client.h>
#include <hse/error/merr.h>
#include <hse/rest/headers.h>
#include <hse/rest/status.h>
#include <hse/util/base.h>
#include <hse/util/data_tree.h>
#include <hse/util/event_counter.h>

#include <hse/test/mtf/framework.h>

char socket_path[PATH_MAX];
char rest_socket_path_param[PATH_MAX + PATH_MAX / 2];
char *gparams[2];

void
mtf_get_global_params(size_t * const paramc, char *** const paramv)
{
    snprintf(socket_path, sizeof(socket_path), "/tmp/hse-global_rest_test-%d.sock", getpid());
    snprintf(
        rest_socket_path_param, sizeof(rest_socket_path_param), "rest.socket_path=%s", socket_path);

    gparams[0] = "rest.enabled=true";
    gparams[1] = rest_socket_path_param;

    *paramc = NELEM(gparams);
    *paramv = gparams;
}

static int
collection_pre(struct mtf_test_info * const lcl_ti)
{
    return merr_errno(rest_client_init(socket_path));
}

static int
collection_post(struct mtf_test_info * const lcl_ti)
{
    rest_client_fini();

    return 0;
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
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    const long *needed = arg;

    return *needed == status ? 0 : status_to_error(status);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(global_rest_test, collection_pre, collection_post)

static merr_t
check_events_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
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

MTF_DEFINE_UTEST(global_rest_test, events)
{
    merr_t err;
    char long_path[DT_PATH_MAX + 1];
    long status = REST_STATUS_BAD_REQUEST;
    int lineno;

    ev(1);
    lineno = __LINE__;

    memset(long_path, 'a', sizeof(long_path));
    long_path[DT_PATH_MAX] = '\0';

    err =
        rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/events/%s", long_path);
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err =
        rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/events/does-not-exist");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_events_cb, NULL, "/events");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/events?pretty=xyz");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch(
        "GET", NULL, NULL, 0, check_events_cb, NULL, "/events/%s/%s/%d", basename(__FILE__),
        __FUNCTION__, lineno);
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_kmc_vmstat_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
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

MTF_DEFINE_UTEST(global_rest_test, kmc_vmstat)
{
    merr_t err;
    long status = REST_STATUS_BAD_REQUEST;

    err = rest_client_fetch("GET", NULL, NULL, 0, check_kmc_vmstat_cb, NULL, "/kmc/vmstat");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err =
        rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/kmc/vmstat?pretty=xyz");
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_params_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
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

MTF_DEFINE_UTEST(global_rest_test, params)
{
    merr_t err;
    long status = REST_STATUS_METHOD_NOT_ALLOWED;

    err = rest_client_fetch("DELETE", NULL, NULL, 0, check_status_cb, &status, "/params");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("PUT", NULL, NULL, 0, check_status_cb, &status, "/params");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_params_cb, NULL, "/params");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/params?pretty=xyz");
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_logging_level_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
{
    if (status != REST_STATUS_OK)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON)))
        return merr(EINVAL);

    if (strncmp(output, arg, output_len) != 0)
        return merr(EINVAL);

    return 0;
}

MTF_DEFINE_UTEST(global_rest_test, params_specific)
{
    merr_t err;
    struct curl_slist *headers = NULL;
    long status = REST_STATUS_METHOD_NOT_ALLOWED;

    headers = curl_slist_append(
        headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON));
    ASSERT_NE(NULL, headers);

    err = rest_client_fetch(
        "DELETE", NULL, NULL, 0, check_status_cb, &status, "/params/rest.enabled");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch(
        "GET", NULL, NULL, 0, check_logging_level_cb, "true", "/params/logging.enabled");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err =
        rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/params/does-not-exist");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_BAD_REQUEST;
    err = rest_client_fetch(
        "PUT", headers, NULL, 0, check_status_cb, &status, "/params/logging.level");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("PUT", NULL, "1", 1, check_status_cb, &status, "/params/logging.level");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch(
        "GET", NULL, NULL, 0, check_status_cb, &status, "/params/logging.level?pretty=xyz");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_LOCKED;
    err = rest_client_fetch(
        "PUT", headers, "1", 1, check_status_cb, &status, "/params/logging.level");
    ASSERT_EQ(0, merr_errno(err));

    curl_slist_free_all(headers);
}

static merr_t
check_perfc_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
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

MTF_DEFINE_UTEST(global_rest_test, perfc)
{
    merr_t err;
    char long_path[DT_PATH_MAX + 1];
    long status = REST_STATUS_BAD_REQUEST;

    memset(long_path, 'a', sizeof(long_path));
    long_path[DT_PATH_MAX] = '\0';

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/perfc/%s", long_path);
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/perfc?pretty=xyz");
    ASSERT_EQ(0, merr_errno(err));

    status = REST_STATUS_NOT_FOUND;
    err =
        rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/perfc/does-not-exist");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_perfc_cb, NULL, "/perfc");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch(
        "GET", NULL, NULL, 0, check_perfc_cb, NULL, "/perfc/global/KVDBMETRICS/set");
    ASSERT_EQ(0, merr_errno(err));
}

static merr_t
check_workqueues_cb(
    const long status,
    const char * const headers,
    const size_t headers_len,
    const char * const output,
    const size_t output_len,
    void * const arg)
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

MTF_DEFINE_UTEST(global_rest_test, workqueues)
{
    merr_t err;
    long status = REST_STATUS_BAD_REQUEST;

    err = rest_client_fetch("GET", NULL, NULL, 0, check_workqueues_cb, NULL, "/workqueues");
    ASSERT_EQ(0, merr_errno(err));

    err =
        rest_client_fetch("GET", NULL, NULL, 0, check_status_cb, &status, "/workqueues?pretty=xyz");
    ASSERT_EQ(0, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(global_rest_test)
