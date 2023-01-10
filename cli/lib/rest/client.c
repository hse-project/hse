/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022-2023 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>

#include <bsd/string.h>
#include <curl/curl.h>

#include <hse/cli/rest/client.h>
#include <hse/error/merr.h>

#include <hse/util/compiler.h>

#include "buffer.h"

#define HOST "http://localhost"

static CURL *parent;

merr_t
rest_client_init(const char *const socket_path)
{
    CURLcode code;

    if (parent)
        return 0;

    if (!socket_path)
        return merr(EINVAL);

    curl_global_init(0);

    parent = curl_easy_init();
    if (!parent)
        return merr(ENOMEM);

    code = curl_easy_setopt(parent, CURLOPT_UNIX_SOCKET_PATH, socket_path);
    if (code != CURLE_OK) {
        curl_easy_cleanup(parent);
        parent = NULL;
        curl_global_cleanup();
        return merrx(EINVAL, code);
    }

    return 0;
}

static size_t
collect_data(char *const ptr, const size_t size, const size_t nmemb, void *const user_data)
{
    merr_t err;
    struct buffer *buf = user_data;
    const size_t total = size * nmemb;

    err = buffer_append(buf, ptr, total);
    if (err)
        return 0;

    return total;
}

merr_t
rest_client_fetch(
    const char *const method,
    struct curl_slist *const headers,
    const char *const data,
    const size_t data_len,
    const rest_client_cb cb,
    void *arg,
    const char *const path_format,
    ...)
{
    int rc;
    va_list args;
    char buf[PATH_MAX];

    if (!parent || !method || !path_format)
        return merr(EINVAL);

    va_start(args, path_format);
    rc = vsnprintf(buf, sizeof(buf), path_format, args);
    va_end(args);

    if (rc >= sizeof(buf) - sizeof(HOST) + 1) {
        return merr(ENAMETOOLONG);
    } else if (rc < 0) {
        return merr(EBADMSG);
    }

    return rest_client_fetch_s(method, headers, data, data_len, cb, arg, buf);
}

merr_t
rest_client_fetch_s(
    const char *method,
    struct curl_slist *headers,
    const char *data,
    const size_t data_len,
    const rest_client_cb cb,
    void *arg,
    const char *path)
{
    int rc;
    merr_t err = 0;
    CURLcode code;
    CURL *req;
    long status;
    struct buffer headers_buf = { 0 };
    struct buffer output_buf = { 0 };
    char buf[PATH_MAX + PATH_MAX / 2];

    if (!parent || !method || !path)
        return merr(EINVAL);

    rc = snprintf(buf, sizeof(buf), "%s%s", HOST, path);
    if (rc >= sizeof(buf) - sizeof(HOST) + 1) {
        return merr(ENAMETOOLONG);
    } else if (rc < 0) {
        return merr(EBADMSG);
    }

    err = buffer_init(&headers_buf, 4096);
    if (err)
        return err;

    err = buffer_init(&output_buf, 4096);
    if (err)
        return err;

    req = curl_easy_duphandle(parent);
    if (!req) {
        err = merr(ENOMEM);
        goto out;
    }

    code = curl_easy_setopt(req, CURLOPT_URL, buf);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    if (data) {
        code = curl_easy_setopt(req, CURLOPT_POSTFIELDS, data);
        if (code != CURLE_OK) {
            err = merrx(ECANCELED, code);
            goto out;
        }

        code = curl_easy_setopt(req, CURLOPT_POSTFIELDSIZE_LARGE, (curl_off_t)data_len);
        if (code != CURLE_OK) {
            err = merrx(ECANCELED, code);
            goto out;
        }
    }

    if (headers) {
        code = curl_easy_setopt(req, CURLOPT_HTTPHEADER, headers);
        if (code != CURLE_OK) {
            err = merrx(ECANCELED, code);
            goto out;
        }
    }

    code = curl_easy_setopt(req, CURLOPT_CUSTOMREQUEST, method);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    code = curl_easy_setopt(req, CURLOPT_WRITEFUNCTION, collect_data);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    code = curl_easy_setopt(req, CURLOPT_WRITEDATA, &output_buf);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    code = curl_easy_setopt(req, CURLOPT_HEADERFUNCTION, collect_data);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    code = curl_easy_setopt(req, CURLOPT_HEADERDATA, &headers_buf);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    code = curl_easy_perform(req);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    code = curl_easy_getinfo(req, CURLINFO_RESPONSE_CODE, &status);
    if (code != CURLE_OK) {
        err = merrx(ECANCELED, code);
        goto out;
    }

    if (cb) {
        err = cb(status, headers_buf.data, headers_buf.len, output_buf.data, output_buf.len, arg);
        if (err)
            goto out;
    }

out:
    buffer_destroy(&headers_buf);
    buffer_destroy(&output_buf);
    curl_easy_cleanup(req);

    return err;
}

void
rest_client_fini()
{
    if (!parent)
        return;

    curl_easy_cleanup(parent);
    curl_global_cleanup();

    parent = NULL;
}
