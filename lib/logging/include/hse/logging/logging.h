/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LOGGING_LOGGING_H
#define HSE_LOGGING_LOGGING_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <syslog.h>

#include <hse_util/compiler.h>

#include <hse/error/merr.h>

/* clang-format off */

#ifndef LOG_DEFAULT
#define LOG_DEFAULT LOG_DEBUG
#endif

#ifdef HSE_RELEASE_BUILD
#define LOG_SQUELCH_NS_DEFAULT (1000 * 1000)
#else
#define LOG_SQUELCH_NS_DEFAULT (0)
#endif

enum log_destination {
    LOG_DEST_STDOUT,
    LOG_DEST_STDERR,
    LOG_DEST_FILE,
    LOG_DEST_SYSLOG,
};

#define LOG_DEST_MIN   LOG_DEST_STDOUT
#define LOG_DEST_MAX   LOG_DEST_SYSLOG
#define LOG_DEST_COUNT (LOG_DEST_MAX + 1)

struct logging_params {
    int lp_level;
    bool lp_enabled;
    uint64_t lp_squelch_ns;
    enum log_destination lp_destination;
    char lp_path[PATH_MAX];
};

#define log_pri(_lvl, _err, _fmt, ...)                           \
    do {                                                         \
        static uint64_t log_timer = 0;                           \
                                                                 \
        log_impl((_lvl), REL_FILE(__FILE__), __LINE__, __func__, \
            &log_timer, (_err), (_fmt), ##__VA_ARGS__);  \
    } while (0)

/* Main logging APIs for HSE.
 */
#define log_debug(_fmt, ...)    log_pri(LOG_DEBUG, 0, (_fmt), ##__VA_ARGS__)
#define log_info(_fmt, ...)     log_pri(LOG_INFO, 0, (_fmt), ##__VA_ARGS__)
#define log_warn(_fmt, ...)     log_pri(LOG_WARNING, 0, (_fmt), ##__VA_ARGS__)
#define log_err(_fmt, ...)      log_pri(LOG_ERR, 0, (_fmt), ##__VA_ARGS__)
#define log_crit(_fmt, ...)     log_pri(LOG_CRIT, 0, (_fmt), ##__VA_ARGS__)

/* Emit logs with pretty printed merr_t values
 */
#define log_warnx(_fmt, _err, ...)  log_pri(LOG_WARNING, (_err), (_fmt), ##__VA_ARGS__)
#define log_errx(_fmt, _err, ...)   log_pri(LOG_ERR, (_err), (_fmt), ##__VA_ARGS__)

/* Helper API used by above log macros. Not intended to be called directly. */
void
log_impl(
    int level,
    const char *file,
    int lineno,
    const char *func,
    uint64_t *timer,
    merr_t err,
    const char *fmt,
    ...) HSE_PRINTF(7, 8);

/* Convert a log level: numeric to string. */
const char *
log_level_to_string(int level);

/* Convert a log level: string to numeric. */
int
log_level_from_string(const char *name);

void
logging_fini(void) HSE_COLD;

merr_t
logging_init(const struct logging_params *params) HSE_COLD;

void
logging_set_level(int level);

#endif /* HSE_LOGGING_LOGGING_H */
