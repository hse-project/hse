/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_REST_RESPONSE_H
#define HSE_REST_RESPONSE_H

#include <stdio.h>
#include <stddef.h>

#include <hse/rest/forward.h>

struct rest_response {
    struct rest_headers *rr_headers;
    FILE *rr_stream;
};

#endif
