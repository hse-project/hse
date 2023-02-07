/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_REST_RESPONSE_H
#define HSE_REST_RESPONSE_H

#include <stdio.h>
#include <stddef.h>

#include <hse/error/merr.h>
#include <hse/rest/forward.h>

struct rest_response {
    struct rest_headers *rr_headers;
    FILE *rr_stream;
};

enum rest_status
rest_response_perror(
    struct rest_response *resp,
    enum rest_status status,
    const char *detail,
    merr_t origin);

#endif
