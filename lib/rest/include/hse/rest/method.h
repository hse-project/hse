/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_REST_METHOD_H
#define HSE_REST_METHOD_H

enum rest_method {
    REST_METHOD_GET,
    REST_METHOD_POST,
    REST_METHOD_HEAD,
    REST_METHOD_PUT,
    REST_METHOD_DELETE,
    REST_METHOD_OPTIONS,
    REST_METHOD_TRACE,
    REST_METHOD_CONNECT,
    REST_METHOD_PATCH,
};

#define REST_METHOD_MIN   REST_METHOD_GET
#define REST_METHOD_MAX   REST_METHOD_PATCH
#define REST_METHOD_COUNT (REST_METHOD_MAX + 1)

#endif
