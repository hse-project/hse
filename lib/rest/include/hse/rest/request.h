/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#ifndef HSE_REST_REQUEST_H
#define HSE_REST_REQUEST_H

#include <stddef.h>

#include <hse/rest/forward.h>

struct rest_request {
    const char *rr_matched;
    const char *rr_actual;
    const struct rest_headers *rr_headers;
    const struct rest_params *rr_params;
    const char *rr_data;
    size_t rr_data_len;
};

#endif
