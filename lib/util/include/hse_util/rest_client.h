/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UI_REST_CLI_H
#define HSE_UI_REST_CLI_H

#include <curl/curl.h>

#include <error/merr.h>
#include <hse_util/rest_api.h>

#pragma GCC visibility push(default)

/**
 * curl_get() -
 * @path:   url following "http://localhost"
 * @sock:   unix socket of the rest port
 * @buf:    (output)rest api output
 * @buf_sz: size of buf
 */
merr_t
curl_get(const char *path, const char *sock, char *buf, size_t buf_size);

/**
 * curl_put() -
 * @path:      url following "http://localhost" including kv pairs at the end
 * @sock:      unix socket of the rest port
 * @data:      (optional)data to be uploaded
 * @data_size: size of data
 * @resp:      (optional)response
 * @resp_size: size of buf
 */
merr_t
curl_put(
    const char *path,
    const char *sock,
    const char *data,
    size_t      data_size,
    char *      resp,
    size_t      resp_size);

#pragma GCC visibility pop

#endif /* HSE_UI_REST_CLI_H */
