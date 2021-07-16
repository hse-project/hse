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

typedef enum {
    HSE_EMERG_VAL,
    HSE_ALERT_VAL,
    HSE_CRIT_VAL,
    HSE_ERR_VAL,
    HSE_WARNING_VAL,
    HSE_NOTICE_VAL,
    HSE_INFO_VAL,
    HSE_DEBUG_VAL,
} log_priority_t;

#endif
