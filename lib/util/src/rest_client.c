/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/minmax.h>
#include <hse_util/logging.h>
#include <hse_util/rest_client.h>
#include <hse_util/event_counter.h>

struct resp_buf {
    char * data;
    size_t len;
    size_t off;
    bool   full;
};

static size_t
resp_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct resp_buf *r = stream;
    size_t           len = size * nmemb;

    if (!r->data)
        return 0; /* no buffer provided */

    /* Check if there's enough space in output buffer.
     * If not, modify last few bytes to an ellipsis and pretend to have
     * written all bytes to avoid a communication error and return.
     */
    if (r->full)
        return len;

    if (r->off + len > r->len) {
        const char * el = " ...\n";
        const size_t n = strlen(el) + 1;

        if (r->off > n)
            memcpy(r->data + r->off - n, el, n);

        r->full = true;
        return len;
    }

    memcpy(r->data + r->off, ptr, len);
    r->off += len;
    return len;
}

merr_t
curl_get(const char *path, const char *sock, char *buf, size_t buf_size)
{
    CURL *          curl;
    CURLcode        res;
    const char *    url_pfx = "http://localhost";
    char            url[strlen(url_pfx) + PATH_MAX + 2];
    merr_t          err = 0;
    long            http_code = MHD_HTTP_NOT_FOUND;
    struct resp_buf resp = {
        .data = buf, .len = buf_size, .off = 0, .full = false,
    };

    if (!path || !sock)
        return merr(ev(EINVAL));

    snprintf(url, sizeof(url), "%s%s%s", url_pfx, path[0] == '/' ? "" : "/", path);

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, sock);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            err = merr(ev(ECOMM));

        /* Ensure response is NULL terminated */
        if (resp.off < resp.len)
            resp.data[resp.off] = '\0';
        else if (resp.len > 0)
            resp.data[resp.len - 1] = '\0';

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_easy_cleanup(curl);
    } else {
        err = merr(ev(EINVAL));
    }

    if (err == 0) {
        err = http_code == MHD_HTTP_OK ? 0 : merr(ev(ENOANO));
        hse_log(HSE_INFO "http response code: %ld", http_code);
    }

    return err;
}

struct upload_buf {
    const char *data;
    size_t      remaining;
    int         off;
};

static size_t
upload_cb(void *ptr, size_t size, size_t nmemb, void *stream)
{
    struct upload_buf *b = stream;
    size_t             len = min((size * nmemb), b->remaining);

    if (!b->data)
        return 0; /* no data to upload */

    if (b->remaining <= 0)
        return 0;

    memcpy(ptr, b->data + b->off, len);
    b->remaining -= len;
    b->off += len;

    return len;
}

merr_t
curl_put(
    const char *path,
    const char *sock,
    const char *data,
    size_t      data_size,
    char *      buf,
    size_t      buf_size)
{
    CURL *      curl;
    CURLcode    res;
    const char *url_pfx = "http://localhost";
    char        url[strlen(url_pfx) + PATH_MAX + 2];
    merr_t      err = 0;
    long        http_code = MHD_HTTP_NOT_FOUND;

    struct upload_buf up = {.data = data, .remaining = data_size, .off = 0 };
    struct resp_buf   resp = {
        .data = buf, .len = buf_size, .off = 0, .full = false,
    };

    if (!path || !sock)
        return merr(ev(EINVAL));

    snprintf(url, sizeof(url), "%s%s%s", url_pfx, path[0] == '/' ? "" : "/", path);

    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *chunk = 0;

        chunk = curl_slist_append(chunk, "Transfer-Encoding: chunked");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_NOPROXY, "*");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, resp_cb);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&resp);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_cb);
        curl_easy_setopt(curl, CURLOPT_READDATA, (void *)&up);

        curl_easy_setopt(curl, CURLOPT_PUT, 1);
        curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, sock);

        res = curl_easy_perform(curl);
        if (res != CURLE_OK)
            err = merr(ev(ECOMM));

        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
        curl_slist_free_all(chunk);
        curl_easy_cleanup(curl);
    } else {
        err = merr(ev(EINVAL));
    }

    if (err == 0)
        err = http_code == MHD_HTTP_OK ? 0 : merr(ev(ENOANO));

    return err;
}
