/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/data_tree.h>
#include <hse_util/rest_api.h>
#include <hse_util/rest_client.h>
#include <hse_util/string.h>

#include <rbtree.h>
#include <curl/curl.h>
#include <pthread.h>

#include "../src/rest_dt.h"

#define SOCK "/tmp/r_api_mp.r_api_kv.rest"

char sock[PATH_MAX];

static int
set_sock(struct mtf_test_info *ti)
{
    snprintf(sock, sizeof(sock), "%s.%d", SOCK, getpid());
    return 0;
}

static int
rest_start(struct mtf_test_info *ti)
{
    rest_server_start(sock);
    return 0;
}

static int
rest_stop(struct mtf_test_info *ti)
{
    rest_server_stop();
    rest_destroy();
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(rest_api, set_sock);

MTF_DEFINE_UTEST(rest_api, start_stop_server)
{
    int ret;

    ret = rest_server_start(sock);
    ASSERT_EQ(ret, 0);
    rest_server_stop();

    /* Multiple calls to rest_server_stop should cause
     * the call to return without doing anything
     */
    rest_server_stop();
    rest_server_stop();
}

MTF_DEFINE_UTEST_PREPOST(rest_api, get_handler_test, rest_start, rest_stop)
{
    char        buf[64 * 1024];
    merr_t      err;
    const char *path;

    ev(1);

    /* Register the alias "test_dt" to send requests to DT */
    rest_init();
    err = rest_url_register(0, 0, rest_dt_get, rest_dt_put, "test_dt");
    ASSERT_EQ(0, err);

    path = "/test_dt/events";
    memset(buf, 0, sizeof(buf));
    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(err, 0);

    /* Invalid(NULL) path */
    path = "/test_dt/events";
    memset(buf, 0, sizeof(buf));
    err = curl_get(0, sock, buf, sizeof(buf));
    ASSERT_EQ(merr_errno(err), EINVAL);
}

MTF_DEFINE_UTEST_PREPOST(rest_api, put_handler_test, rest_start, rest_stop)
{
    char                  buf[64 * 1024];
    merr_t                err;
    char                  path[DT_PATH_MAX];
    char                  full_path[DT_PATH_MAX];
    int                   line;
    struct event_counter *ec;
    struct dt_element *   dte;

    rest_init();

    err = rest_url_register(0, 0, rest_dt_get, rest_dt_put, "data");
    ASSERT_EQ(0, err);

    /* clang-format off */
    ev(1); line = __LINE__;
    /* clang-format on */

    snprintf(
        full_path,
        sizeof(full_path),
        "%s/%s/%s/%d",
        DT_PATH_EVENT,
        basename(__FILE__),
        __func__,
        line);

    /* Get the dt element that the upcoming tests will attempt to modify */
    dte = dt_find(full_path, 1);
    ASSERT_NE(NULL, dte);

    ec = dte->dte_data;

    /* Normal Working */
    ASSERT_EQ(ec->ev_trip_odometer, 0);
    strcpy(path, full_path + 1);
    strcat(path, "?trip_od=1");
    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    /* check in dt_tree if trip odometer is non-zero */
    ASSERT_EQ(1, ec->ev_trip_odometer);

    /* Ends on some random arg */
    strcpy(path, full_path + 1);
    strcat(path, "?trip_od=1&just_a_word");
    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    /* Empty field */
    strcpy(path, full_path + 1);
    strcat(path, "?trip_od=1&=abcd");
    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    /* Empty value */
    strcpy(path, full_path + 1);
    strcat(path, "?trip_od=1&abcd=");
    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    /* Sets a priority */
    strcpy(path, full_path + 1);
    strcat(path, "?trip_od=1&pri=HSE_INFO");
    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    /* nonexistent dt path */
    const char *invalid_path = "Invalid path";

    snprintf(path, sizeof(path), "%s/event_counter_no_really?trip_od=1", DT_PATH_ROOT);
    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, strncmp(invalid_path, buf, strlen(invalid_path)));
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(rest_api, no_handlers_test, rest_start, rest_stop)
{
    merr_t err;

    rest_init();

    err = rest_url_register(0, 0, 0, 0, "no/handlers");
    ASSERT_EQ(EINVAL, merr_errno(err));

    rest_destroy();

    rest_destroy(); /* test that destroy is idempotent */
}

MTF_DEFINE_UTEST_PREPOST(rest_api, register_before_init, rest_start, rest_stop)
{
    merr_t err;

    err = rest_url_register(0, 0, 0, 0, "yet/to/init");
    ASSERT_EQ(EINVAL, merr_errno(err));
}

static merr_t
parallel_test_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    atomic_inc((atomic_t *)context);

    return 0;
}

void *
parallel_rest_req(void *info)
{
    char        buf[4096] = { 0 };
    const char *path = "parallel/rest/req";
    merr_t      err;

    err = curl_get(path, sock, buf, sizeof(buf));
    if (err)
        atomic_inc((atomic_t *)info);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(rest_api, multisession_test, rest_start, rest_stop)
{
    char *    path = "parallel/rest/req";
    merr_t    err;
    atomic_t  calls;
    atomic_t  failures;
    const int num_threads = 5;
    pthread_t t[num_threads];
    int       i, rc;

    rest_init();
    atomic_set(&calls, 0);
    atomic_set(&failures, 0);

    err = rest_url_register(&calls, 0, parallel_test_get, 0, path);
    ASSERT_EQ(0, err);

    /* initialize libcurl before starting threads that call curl APIs */
    curl_global_init(CURL_GLOBAL_ALL);

    for (i = 0; i < num_threads; ++i) {
        rc = pthread_create(t + i, 0, parallel_rest_req, &failures);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; ++i) {
        rc = pthread_join(t[i], 0);
        ASSERT_EQ(0, rc);
    }

    ASSERT_EQ(0, atomic_read(&failures));
    ASSERT_EQ(num_threads, atomic_read(&calls));
}

static merr_t
get_path(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    ssize_t *len = context;

    return write(info->resp_fd, path, *len) == *len ? 0 : errno;
}

MTF_DEFINE_UTEST_PREPOST(rest_api, reg_too_many_urls, rest_start, rest_stop)
{
    const int num_urls = 1000;
    char      url[32];
    char      buf[32];
    int       i;
    size_t    len;
    merr_t    err;

    rest_init();

    len = sizeof(buf);

    for (i = 0; i < num_urls; i++) {
        snprintf(url, sizeof(url), "url%d", i);
        err = rest_url_register(&len, 0, get_path, 0, url);
        ASSERT_EQ(0, err);
    }

    for (i = 0; i < num_urls; i++) {
        memset(buf, 0, sizeof(buf));
        snprintf(url, sizeof(url), "url%d", i);
        err = curl_get(url, sock, buf, sizeof(buf));
        ASSERT_EQ(0, err);
        ASSERT_STREQ(url, buf);
    }
}

static merr_t
get_url(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    const size_t url_len = strlen(url);

    return write(info->resp_fd, url, url_len) == url_len ? 0 : errno;
}

MTF_DEFINE_UTEST_PREPOST(rest_api, url_length_test, rest_start, rest_stop)
{
    char   url[REST_URL_LEN_MAX + 1];
    char   buf[REST_URL_LEN_MAX + 1] = { 0 };
    size_t sz;
    int    i;
    merr_t err;

    sz = sizeof(url);
    for (i = 0; i < sz; i++)
        url[i] = 'a';
    url[sz - 2] = 'b';
    url[sz - 1] = '\000';

    rest_init();

    err = rest_url_register(0, 0, get_url, 0, url);
    ASSERT_EQ(ENAMETOOLONG, merr_errno(err));

    url[sz - 2] = '\000';
    err = rest_url_register(0, 0, get_url, 0, url);
    ASSERT_EQ(0, err);

    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_STREQ(url, buf);

    err = curl_get("", sock, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(rest_api, nonexistent_urls, rest_start, rest_stop)
{
    const char *url = "non/existent/url";
    char        buf[1024] = { 0 };
    merr_t      err;

    rest_init();

    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));

    err = curl_get("", sock, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(rest_api, rest_url_deregister_test, rest_start, rest_stop)
{
    int    i;
    merr_t err;
    char   buf[1024];

    err = rest_url_deregister("before/init");
    ASSERT_EQ(EINVAL, merr_errno(err));

    rest_init();

    err = rest_url_deregister("url/not/registered");
    ASSERT_EQ(ENOENT, merr_errno(err));

    for (i = 0; i < 4; i++) {
        err = rest_url_register(0, 0, get_url, 0, "url/%d", i);
        ASSERT_EQ(0, err);
    }

    err = rest_url_deregister("url/%d", 2);
    ASSERT_EQ(0, err);

    for (i = 0; i < 4; i++) {
        char url[16];

        snprintf(url, sizeof(url), "url/%d", i);

        err = curl_get(url, sock, buf, sizeof(buf));
        if (i == 2) {
            ASSERT_EQ(ENOANO, merr_errno(err));
        } else {
            ASSERT_EQ(0, err);
            ASSERT_EQ(0, strncmp(url, buf, strlen(url)));
        }
    }
}

#define IS_VALID_SYMS(c) (c == '.' || c == '/' || c == '-' || c == '_' || c == ':')

MTF_DEFINE_UTEST_PREPOST(rest_api, unsupported_characters, rest_start, rest_stop)
{
    merr_t        err;
    char          kbuf[URL_KLEN_MAX + 2];
    char          vbuf[URL_VLEN_MAX + 2];
    char          url[(sizeof(kbuf) + sizeof(vbuf)) * 2];
    char          buf[4096];
    unsigned char c;

    rest_init();

    /* Try all characters except NULL(0) */
    for (c = 255; c > 0; c--) {
        err = rest_url_register(0, 0, get_url, 0, "un/supp/url%c", c);
        if (isalnum(c) || IS_VALID_SYMS(c))
            ASSERT_EQ(0, err);
        else
            ASSERT_EQ(EINVAL, merr_errno(err));
    }

    /* key/value too long */
    memset(kbuf, 'k', sizeof(kbuf));
    kbuf[sizeof(kbuf) - 1] = 0;

    memset(vbuf, 'v', sizeof(vbuf));
    vbuf[sizeof(vbuf) - 1] = 0;

    snprintf(url, sizeof(url), "un/supp/urlx?%s", kbuf);
    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));

    snprintf(url, sizeof(url), "un/supp/urlx?arg=%s", vbuf);
    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));

    /* max length */
    kbuf[URL_KLEN_MAX] = '\000';
    snprintf(url, sizeof(url), "un/supp/urlx?%s", kbuf);
    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);

    vbuf[URL_VLEN_MAX] = '\000';
    snprintf(url, sizeof(url), "un/supp/urlx?arg=%s", vbuf);
    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(rest_api, too_many_kv, rest_start, rest_stop)
{
    const int   nkv = 17;
    const char *kv = "a=b&";
    char        str[4 * nkv];
    size_t      max = sizeof(str);
    merr_t      err;
    char        url[sizeof(str) + 15];
    int         i;
    char        buf[4096];

    rest_init();

    err = rest_url_register(0, 0, get_url, 0, "too/many/kv");
    ASSERT_EQ(0, err);

    for (i = 0; i < max; i += 4)
        memcpy(str + i, kv, strlen(kv));
    str[max - 1] = 0; /* replace last ampersand with null */

    snprintf(url, sizeof(url), "too/many/kv?%s", str);
    err = curl_get(url, sock, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));
}

MTF_END_UTEST_COLLECTION(rest_api)
