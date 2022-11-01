/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stdbool.h>

#include <hse/error/merr.h>
#include <hse/rest/headers.h>
#include <hse/rest/response.h>
#include <hse/rest/status.h>
#include <hse/util/event_counter.h>
#include <hse/util/err_ctx.h>

#include "response.h"
#include "status.h"

enum rest_status
rest_response_perror(
    struct rest_response *const resp,
    const enum rest_status status,
    const char *const detail,
    const merr_t origin)
{
    merr_t err;
    const char *reason;

    if (!resp || status < 400 || status > 500 || !detail || !origin) {
        ev(1);
        return status;
    }

    reason = status_to_reason(status);

    err = rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_PROBLEM_JSON);
    ev(err);

    fprintf(resp->rr_stream, RFC7807_FMT, reason, status, detail, merr_file(origin),
        merr_lineno(origin), merr_errno(origin));

    return status;
}
