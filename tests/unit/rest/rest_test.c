/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <limits.h>
#include <pthread.h>

#include <mtf/framework.h>

#include <hse/cli/rest/client.h>
#include <hse/rest/headers.h>
#include <hse/rest/request.h>
#include <hse/rest/response.h>
#include <hse/rest/server.h>
#include <hse/rest/status.h>

#include <hse/error/merr.h>

char socket_path[PATH_MAX];

enum rest_status
ok(const struct rest_request *const req, struct rest_response *const resp, void *const ctx)
{
    return REST_STATUS_OK;
}

enum rest_status
body(const struct rest_request *const req, struct rest_response *const resp, void *const ctx)
{
    merr_t err;

    fputs("\"hello world\"", resp->rr_stream);

    err = rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON);
    if (err)
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    return REST_STATUS_OK;
}

static rest_handler *handlers[][REST_METHOD_COUNT] = {
    {
        [REST_METHOD_GET] = ok,
        [REST_METHOD_POST] = ok,
        [REST_METHOD_PUT] = ok,
    },
    {
        [REST_METHOD_GET] = body,
    },
};

int
collection_pre(struct mtf_test_info *const lcl_ti)
{
    snprintf(socket_path, sizeof(socket_path), "/tmp/hse-%s-%d.sock",
        lcl_ti->ti_coll->tci_coll_name, getpid());

    return merr_errno(rest_client_init(socket_path));
}

int
collection_post(struct mtf_test_info *const lcl_ti)
{
    rest_client_fini();

    return 0;
}

int
test_pre(struct mtf_test_info *const lcl_ti)
{
    merr_t err;

    err = rest_server_start(socket_path);

    return merr_errno(err);
}

int
test_post(struct mtf_test_info *lcl_ti)
{
    rest_server_stop();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(rest_test, collection_pre, collection_post)

MTF_DEFINE_UTEST(rest_test, start_server)
{
    merr_t err;

    err = rest_server_start(NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(rest_test, add_endpoint, test_pre, test_post)
{
    merr_t err;

    /* Bad flags */
    err = rest_server_add_endpoint(81, handlers[0], NULL, "test");
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = rest_server_add_endpoint(0, handlers[0], NULL, "test");
    ASSERT_EQ(0, merr_errno(err));

    /* Duplicate endpoint */
    err = rest_server_add_endpoint(0, handlers[0], NULL, "test");
    ASSERT_EQ(ENOTUNIQ, merr_errno(err));

    err = rest_server_remove_endpoint("test");
    ASSERT_EQ(0, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(rest_test, remove_endpoint, test_pre, test_post)
{
    merr_t err;

    /* Endpoint does not exist */
    err = rest_server_remove_endpoint("test");
    ASSERT_EQ(EINVAL, merr_errno(err));
}

struct response_ctx
{
    enum rest_status status;
};

static merr_t
get_status(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    struct response_ctx *ctx = arg;

    ctx->status = status;

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(rest_test, does_not_exist, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/does-not-exist");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_NOT_FOUND, ctx.status);
}

MTF_DEFINE_UTEST_PREPOST(rest_test, allowed_methods, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[0], NULL, "/allowed-methods");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/allowed-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    err = rest_client_fetch("POST", NULL, NULL, 0, get_status, &ctx, "/allowed-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    err = rest_client_fetch("PUT", NULL, NULL, 0, get_status, &ctx, "/allowed-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    err = rest_client_fetch("TRACE", NULL, NULL, 0, get_status, &ctx, "/allowed-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_NOT_IMPLEMENTED, ctx.status);

    rest_server_remove_endpoint("/allowed-methods");
}

MTF_DEFINE_UTEST_PREPOST(rest_test, implemented_methods, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[0], NULL, "/implemented-methods");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/implemented-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    err = rest_client_fetch("POST", NULL, NULL, 0, get_status, &ctx, "/implemented-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    err = rest_client_fetch("PUT", NULL, NULL, 0, get_status, &ctx, "/implemented-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    err = rest_client_fetch("TRACE", NULL, NULL, 0, get_status, &ctx, "/implemented-methods");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_NOT_IMPLEMENTED, ctx.status);

    rest_server_remove_endpoint("/implemented-methods");
}

MTF_DEFINE_UTEST_PREPOST(rest_test, bad_query_string, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[0], NULL, "/example");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/example?yoyo");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_BAD_REQUEST, ctx.status);

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/example?yoyo=&=");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_BAD_REQUEST, ctx.status);

    rest_server_remove_endpoint("/example");
}

MTF_DEFINE_UTEST_PREPOST(rest_test, inexact, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_server_add_endpoint(0, handlers[0], NULL, "/example");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/exampleeeeeeee");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_NOT_FOUND, ctx.status);

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/example/");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_NOT_FOUND, ctx.status);

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/example/test");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    rest_server_remove_endpoint("/example");
}

static merr_t
check_response_body(
    const long status,
    const char *const headers,
    const size_t headers_len,
    const char *const output,
    const size_t output_len,
    void *const arg)
{
    struct response_ctx *ctx = arg;

    ctx->status = status;

    if (strncmp(output, "\"hello world\"", output_len) != 0)
        return merr(EINVAL);

    if (!strstr(headers, REST_MAKE_STATIC_HEADER(REST_HEADER_CONTENT_TYPE,
            REST_APPLICATION_JSON)))
        return merr(EINVAL);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(rest_test, exact, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[0], NULL, "/example");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/example/test");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_NOT_FOUND, ctx.status);

    err = rest_client_fetch("GET", NULL, NULL, 0, get_status, &ctx, "/example");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    rest_server_remove_endpoint("/example");
}

MTF_DEFINE_UTEST_PREPOST(rest_test, response_body, test_pre, test_post)
{
    merr_t err;
    struct response_ctx ctx;

    err = rest_server_add_endpoint(REST_ENDPOINT_EXACT, handlers[1], NULL, "/example");
    ASSERT_EQ(0, merr_errno(err));

    err = rest_client_fetch("GET", NULL, NULL, 0, check_response_body, &ctx, "/example");
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(REST_STATUS_OK, ctx.status);

    rest_server_remove_endpoint("/example");
}

MTF_END_UTEST_COLLECTION(rest_test)
