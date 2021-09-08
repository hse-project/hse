/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_LOGGING_H
#define HSE_CONFIG_LOGGING_H

#include <stdio.h>

#include <hse_ikvdb/param.h>
#include <hse_util/logging.h>

extern bool hse_initialized;

#define CLOG(...)                         \
    do {                                  \
        if (hse_initialized) {            \
            hse_log(HSE_ERR __VA_ARGS__); \
        } else {                          \
            fprintf(stderr, __VA_ARGS__); \
            fprintf(stderr, "\n");        \
        }                                 \
    } while (0)

const char *
params_logging_context(const struct params *const p);

#endif
