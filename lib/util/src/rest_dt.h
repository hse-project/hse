/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_REST_DT_H
#define HSE_PLATFORM_REST_DT_H

#include <hse_util/rest_api.h>

merr_t
rest_dt_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context);

merr_t
rest_dt_put(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context);

#endif /* HSE_PLATFORM_REST_DT_H */
