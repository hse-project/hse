/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_HSE_GPARAMS_H
#define HSE_CONFIG_HSE_GPARAMS_H

#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <sys/un.h>

#include <hse_util/hse_err.h>
#include <hse_util/logging_types.h>
#include <hse_util/compiler.h>

struct hse_gparams {
    uint64_t gp_c0kvs_ccache_sz_max;
    uint64_t gp_c0kvs_ccache_sz;
    uint64_t gp_c0kvs_cheap_sz;
    uint64_t gp_vlb_cache_sz;
    uint8_t  gp_perfc_level;

    struct {
        bool enabled;
        char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    } gp_socket;

    struct {
        bool                 enabled;
        bool                 structured;
        hse_logpri_t         level;
        enum log_destination destination;
        uint64_t             squelch_ns;
        char                 path[PATH_MAX];
    } gp_logging;
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

#endif
