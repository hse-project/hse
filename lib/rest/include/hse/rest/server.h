/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_REST_SERVER_H
#define HSE_REST_SERVER_H

#include <hse/error/merr.h>
#include <hse/rest/forward.h>
#include <hse/rest/method.h>
#include <hse/util/compiler.h>

#define REST_ENDPOINT_EXACT (1U << 1)

/**
 * Callback called when a endpoint is matched upon a request.
 *
 * @param req Request object.
 * @param resp Response object.
 * @param ctx Context passed when endpoint was registered.
 *
 * @returns HTTP status code.
 */
typedef enum rest_status
rest_handler(const struct rest_request *req, struct rest_response *resp, void *ctx);

merr_t
rest_server_add_endpoint(
    unsigned int flags,
    rest_handler *handlers[static REST_METHOD_COUNT],
    void *ctx,
    const char *path_fmt,
    ...) HSE_PRINTF(4, 5);

merr_t
rest_server_remove_endpoint(const char *path_fmt, ...) HSE_PRINTF(1, 2);

merr_t
rest_server_start(const char *socket_path);

void
rest_server_stop(void);

#endif
