/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_CLI_REST_CLIENT_H
#define HSE_CLI_REST_CLIENT_H

#include <curl/curl.h>

#include <hse/error/merr.h>
#include <hse/util/compiler.h>

typedef merr_t (*rest_client_cb)(
    long status,
    const char *headers,
    size_t headers_len,
    const char *output,
    size_t output_len,
    void *arg);

merr_t
rest_client_init(const char *socket_path);

/**
 * This function is only exported for the purpose of writing tests and the
 * hsettp tool.
 */
merr_t
rest_client_fetch(
    const char *method,
    struct curl_slist *headers,
    const char *data,
    size_t data_len,
    rest_client_cb,
    void *arg,
    const char *path_format,
    ...) HSE_PRINTF(7, 8);

merr_t
rest_client_fetch_s(
    const char *method,
    struct curl_slist *headers,
    const char *data,
    size_t data_len,
    rest_client_cb,
    void *arg,
    const char *path);

void
rest_client_fini(void);

#endif
