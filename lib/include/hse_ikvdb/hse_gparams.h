/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_HSE_GPARAMS_H
#define HSE_CONFIG_HSE_GPARAMS_H

#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <sys/un.h>

#include <cjson/cJSON.h>

#include <hse/error/merr.h>
#include <hse/logging/logging.h>

#include <hse_util/compiler.h>

struct hse_gparams {
    uint64_t gp_c0kvs_ccache_sz_max;
    uint64_t gp_c0kvs_ccache_sz;
    uint64_t gp_c0kvs_cheap_sz;
    uint64_t gp_vlb_cache_sz;
    uint32_t gp_workqueue_tcdelay;
    uint32_t gp_workqueue_idle_ttl;
    uint8_t  gp_perfc_level;

    struct {
        bool enabled;
        char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    } gp_socket;

    struct logging_params gp_logging;
};

extern struct hse_gparams hse_gparams;

const struct param_spec *
hse_gparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

struct hse_gparams
hse_gparams_defaults(void) HSE_CONST;

merr_t
hse_gparams_get(
    const struct hse_gparams *params,
    const char *              param,
    char *                    buf,
    size_t                    buf_sz,
    size_t *                  needed_sz);

merr_t
hse_gparams_set(
    const struct hse_gparams *params,
    const char *              param,
    const char *              value);

cJSON *
hse_gparams_to_json(const struct hse_gparams *params);

#endif
