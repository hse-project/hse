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
    struct {
        bool enabled;
        char path[sizeof(((struct sockaddr_un *) 0)->sun_path)];
    } gp_socket;
    struct {
        bool                 enabled;
        bool                 structured;
        enum log_destination destination;
        log_priority_t       level;
        uint64_t             squelch_ns;
        char                 path[PATH_MAX];
    } gp_logging;
};

extern struct hse_gparams hse_gparams;

const struct param_spec *
hse_gparams_pspecs_get(size_t *pspecs_sz) HSE_RETURNS_NONNULL;

merr_t
hse_gparams_resolve(struct hse_gparams *params, const char *runtime_home);

struct hse_gparams
hse_gparams_defaults(void) HSE_CONST;

#endif
