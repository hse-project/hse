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

#define CLOG_ERR(...)                     \
    do {                                  \
        if (hse_initialized) {            \
            log_err(__VA_ARGS__);         \
        } else {                          \
            fprintf(stderr, __VA_ARGS__); \
            fputc('\n', stderr);          \
        }                                 \
    } while (0)

#define CLOG_DEBUG(...)                     \
    do {                                    \
        if (hse_initialized) {              \
            log_debug(__VA_ARGS__);         \
        }                                   \
    } while (0)

const char *
params_logging_context(const struct params *const p);

#endif
