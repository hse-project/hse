/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LOGGING_LOGGING_TYPES_H
#define HSE_LOGGING_LOGGING_TYPES_H

enum log_destination {
    LD_STDOUT,
    LD_STDERR,
    LD_FILE,
    LD_SYSLOG,
};

#define LD_MIN   LD_STDOUT
#define LD_MAX   LD_SYSLOG
#define LD_COUNT (LD_MAX + 1)

typedef enum {
    HSE_LOGPRI_EMERG,
    HSE_LOGPRI_ALERT,
    HSE_LOGPRI_CRIT,
    HSE_LOGPRI_ERR,
    HSE_LOGPRI_WARN,
    HSE_LOGPRI_NOTICE,
    HSE_LOGPRI_INFO,
    HSE_LOGPRI_DEBUG
} log_priority_t;

#endif
