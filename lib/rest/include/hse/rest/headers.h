/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_REST_HEADERS_H
#define HSE_REST_HEADERS_H

#include <hse/error/merr.h>

struct rest_headers;

#define REST_MAKE_STATIC_HEADER(_key, _value) (_key ": " _value)

#define REST_HEADER_CONTENT_TYPE "Content-Type"
#define REST_APPLICATION_JSON "application/json"
#define REST_APPLICATION_PROBLEM_JSON "application/problem+json"

const char *
rest_headers_get(const struct rest_headers *headers, const char *key);

merr_t
rest_headers_set(struct rest_headers *headers, const char *key, const char *value);

#endif
