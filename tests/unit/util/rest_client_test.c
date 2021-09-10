/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <unistd.h>

#include <hse_ut/framework.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>
#include <hse_util/rest_api.h>
#include <hse_util/rest_client.h>
#include <hse_util/event_counter.h>

#include <hse/version.h>

char sock[PATH_MAX];

static int
set_sock(struct mtf_test_info *ti)
{
    snprintf(sock, sizeof(sock), "/tmp/hse-%d.sock", getpid());
    return 0;
}

static int
rest_start(struct mtf_test_info *ti)
{
    return merr_errno(rest_server_start(sock));
}

static int
rest_stop(struct mtf_test_info *ti)
{
    rest_server_stop();
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(rest_client, set_sock);

struct _ex1 {
    char text[32];
    int  number;
    int  calls;
} ex1;

static merr_t
ex1_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    char         str[256] = { 0 };
    size_t       bytes;
    struct _ex1 *e = context;

    snprintf(str, sizeof(str), "text:%s,number:%d", e->text, e->number);
    bytes = strnlen(str, sizeof(str));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    write(info->resp_fd, str, bytes);
#pragma GCC diagnostic pop

    return 0;
}

static merr_t
ex1_put(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    char            str[256] = { 0 };
    struct _ex1 *   e = context;
    struct rest_kv *kv;
    size_t          bytes;

    e->calls++;

    while ((kv = rest_kv_next(iter)) != 0) {
        if (strcmp(kv->key, "text") == 0)
            strlcpy(e->text, kv->value, sizeof(e->text));

        if (strcmp(kv->key, "number") == 0)
            e->number = (int)strtoul(kv->value, 0, 0);

        if (strcmp(kv->key, "magic") == 0) {
            strlcpy(e->text, "slartibartfast", sizeof(e->text));
            e->number = 42;
        }
    }

    snprintf(str, sizeof(str), "text:%s,number:%d", e->text, e->number);
    bytes = strnlen(str, sizeof(str));
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
    write(info->resp_fd, str, bytes);
#pragma GCC diagnostic pop

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(rest_client, example1, rest_start, rest_stop)
{
    char * basepath = "this/is/example";
    char * getpath = "this/is/example/one";
    char   buf[4096] = { 0 };
    merr_t err;

    strlcpy(ex1.text, "no_name", sizeof(ex1.text));
    ex1.number = 4;

    /* 1. register our handlers and a context */
    err = rest_url_register(&ex1, 0, ex1_get, ex1_put, "%s/%s", basepath, "one");
    ASSERT_EQ(0, err);

    {
        const char *path = "/version";
        char        expect[4096] = { 0 };

        sprintf(
            expect,
            "HSE REST API Version %d.%d %s\n",
            REST_VERSION_MAJOR,
            REST_VERSION_MINOR,
            HSE_VERSION_STRING);

        err = curl_get(path, sock, buf, sizeof(buf));
        ASSERT_EQ(0, err);
        ASSERT_STREQ(expect, buf);
    }

    memset(buf, 0, sizeof(buf));

    /* 2. update the context externally and verify through get */
    strlcpy(ex1.text, "initial_name", sizeof(ex1.text));
    ex1.number = 10;

    err = curl_get(getpath, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:initial_name,number:10", buf);

    /* 3. update only text and verify */
    const char *putpath1 = "/this/is/example/one?text=new_name";

    memset(buf, 0, sizeof(buf));
    ex1.calls = 0;
    err = curl_put(putpath1, sock, 0, 0, buf, sizeof(buf));
    printf("%s:%d\n", merr_file(err), merr_lineno(err));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:new_name,number:10", buf);
    ASSERT_STREQ("new_name", ex1.text);
    ASSERT_EQ(10, ex1.number);
    ASSERT_EQ(1, ex1.calls);

    memset(buf, 0, sizeof(buf));
    err = curl_get(getpath, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:new_name,number:10", buf);

    /* 4. update both text and number and verify */
    const char *putpath2 = "this/is/example/one?text=newer_name&number=20";

    memset(buf, 0, sizeof(buf));
    ex1.calls = 0;
    err = curl_put(putpath2, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:newer_name,number:20", buf);
    ASSERT_STREQ("newer_name", ex1.text);
    ASSERT_EQ(20, ex1.number);
    ASSERT_EQ(1, ex1.calls);

    memset(buf, 0, sizeof(buf));
    err = curl_get(getpath, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:newer_name,number:20", buf);
}

MTF_DEFINE_UTEST_PREPOST(rest_client, example2, rest_start, rest_stop)
{
    char * getpath = "this/is/example/two";
    char   buf[4096] = { 0 };
    merr_t err;

    strlcpy(ex1.text, "initial_name", sizeof(ex1.text));
    ex1.number = 10;

    /* register our handlers and a context */
    err = rest_url_register(&ex1, 0, ex1_get, ex1_put, getpath);
    ASSERT_EQ(0, err);

    /* only key. no value */
    const char *putpath1 = "this/is/example/two?magic";

    memset(buf, 0, sizeof(buf));
    ex1.calls = 0;
    err = curl_put(putpath1, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:slartibartfast,number:42", buf);
    ASSERT_STREQ("slartibartfast", ex1.text);
    ASSERT_EQ(42, ex1.number);
    ASSERT_EQ(1, ex1.calls);

    memset(buf, 0, sizeof(buf));
    err = curl_get(getpath, sock, buf, sizeof(buf));
    printf("%s:%d\n", merr_file(err), merr_lineno(err));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:slartibartfast,number:42", buf);

    /* key + key-value combo */
    const char *putpath2 = "this/is/example/two?magic&number=111";

    memset(buf, 0, sizeof(buf));
    ex1.calls = 0;
    err = curl_put(putpath2, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:slartibartfast,number:111", buf);
    ASSERT_STREQ("slartibartfast", ex1.text);
    ASSERT_EQ(111, ex1.number);
    ASSERT_EQ(1, ex1.calls);

    memset(buf, 0, sizeof(buf));
    err = curl_get(getpath, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:slartibartfast,number:111", buf);

    /* key-value + key combo */
    const char *putpath3 = "this/is/example/two?number=111&magic";

    memset(buf, 0, sizeof(buf));
    ex1.calls = 0;
    err = curl_put(putpath3, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:slartibartfast,number:42", buf);
    ASSERT_STREQ("slartibartfast", ex1.text);
    ASSERT_EQ(42, ex1.number);
    ASSERT_EQ(1, ex1.calls);

    memset(buf, 0, sizeof(buf));
    err = curl_get(getpath, sock, buf, sizeof(buf));
    ASSERT_EQ(0, err);
    ASSERT_STREQ("text:slartibartfast,number:42", buf);
}

MTF_DEFINE_UTEST_PREPOST(rest_client, unregistered_path, rest_start, rest_stop)
{
    char * getpath = "some/misc/tests";
    char   buf[4096] = { 0 };
    merr_t err;

    /* register our handlers and a context */
    err = rest_url_register(&ex1, 0, ex1_get, ex1_put, getpath);
    ASSERT_EQ(0, err);

    const char *putpath = "this/is/not/the/registered/path";

    memset(buf, 0, sizeof(buf));
    ex1.calls = 0;
    err = curl_put(putpath, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(ENOANO, merr_errno(err));
}

MTF_DEFINE_UTEST(rest_client, no_server)
{
    char * getpath = "some/misc/tests";
    char   buf[4096] = { 0 };
    merr_t err;

    /* register our handlers and a context */
    err = rest_url_register(&ex1, 0, ex1_get, ex1_put, getpath);
    ASSERT_EQ(0, err);

    const char *path = "this/is/not/the/registered/path";

    err = curl_put(path, sock, 0, 0, buf, sizeof(buf));
    ASSERT_EQ(ECOMM, merr_errno(err));

    err = curl_get(path, sock, buf, sizeof(buf));
    ASSERT_EQ(ECOMM, merr_errno(err));
}

#define LONG_STR_SIZE (16 * 1024 * 1024)

/* large buffer get */
static merr_t
large_buf_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    char *  str;
    ssize_t ret;

    str = malloc(LONG_STR_SIZE);
    if (ev(!str))
        return merr(ENOMEM);

    memset(str, 'x', LONG_STR_SIZE);
    ret = rest_write_safe(info->resp_fd, str, LONG_STR_SIZE);
    if (ev(ret < 0))
        return merr(-ret);

    free(str);
    return 0;
}

MTF_DEFINE_UTEST_PREPOST(rest_client, longstr_test, rest_start, rest_stop)
{
    char * getpath = "this/is/a/long/string/test";
    char * big_buf;
    merr_t err;
    int    i;

    big_buf = malloc(LONG_STR_SIZE);
    ASSERT_NE(0, big_buf);

    memset(big_buf, '#', LONG_STR_SIZE);

    /* register our handlers and a context */
    err = rest_url_register((void *)-1, 0, large_buf_get, 0, getpath);
    ASSERT_EQ(0, err);

    err = curl_get(getpath, sock, big_buf, LONG_STR_SIZE);
    ASSERT_EQ(0, err);
    for (i = 0; i < LONG_STR_SIZE - 1; i++)
        ASSERT_EQ('x', big_buf[i]);
    ASSERT_EQ('\0', big_buf[LONG_STR_SIZE - 1]);

    free(big_buf);
}

MTF_END_UTEST_COLLECTION(rest_client)
