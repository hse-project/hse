/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_LOGGING_H
#define HSE_PLATFORM_LOGGING_H

#include <string.h>

#include <hse_util/arch.h>
#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>
#include <hse_util/data_tree.h>
#include <hse_util/event_counter.h>
#include <hse_util/logging_types.h>

#include <syslog.h>

/* clang-format off */

#ifndef HSE_LOGPRI_DEFAULT
#define HSE_LOGPRI_DEFAULT  (HSE_LOGPRI_DEBUG)
#endif

/* Log domain is a prefix for every log statement for grepping related logs
 * across multiple files and functions.
 */
#ifndef LOG_DOMAIN
#define LOG_DOMAIN NULL
#endif

#ifdef __FILE_NAME__
#define log_domain_basename(x) __FILE_NAME__
#else
#if defined(__has_builtin) && __has_builtin(__builtin_strrchr)
#define log_domain_basename(x) (__builtin_strrchr((x), '/') ? __builtin_strrchr((x), '/') + 1 : (x))
#else
#define log_domain_basename(x) (strrchr((x), '/') ? strrchr((x), '/') + 1 : (x))
#endif
#endif

/* The name of a "type" field common to all structured log messages.  Should be
 * somewhat unique to facilitate grepping when structured logs are emitted in
 * non-structured format.
 */
#define SLOG_TYPE_IDENTIFIER "slog"

/*
 * A single log instance can have no more than MAX_HSE_SPECS hse-specific
 * conversion specifiers. For that instance there can be no more than
 * HSE_LOG_NV_PAIRS_MAX of structured log data entries created.
 *
 * As structured name value data is accumulated it must be retained
 * until right before the dynamic call to json payload formatter so that
 * those values can be tacked onto its argument list.
 */
#define HSE_LOG_SPECS_MAX   (10)

/*
 * A single log instance can have no more than HSE_LOG_NV_PAIRS_MAX of structured
 * log data entries created.
 *
 * The need for the space is due to current logging logic that requies the
 * data to be accumulated and passed as a argument to json formatter to
 * generate a json formated payload which is passed as a final argument
 * to syslog in user space or printk_emit in case of kernel.
 * As structured name value data is accumulated it must be retained until
 * those values can be tacked onto its argument list.
 */
#define HSE_LOG_NV_PAIRS_MAX  (40 * HSE_LOG_SPECS_MAX)

/*
 * The HSE platform logging subsystem needs to accept client-registered
 * conversion specifiers.
 *
 * The HSE platform logging subsystem defines a set of HSE-specific conversion
 * specifiers.  For example, one can give "The error: @@e" as a format string
 * to hse_xlog and pass in a pointer to an hse_err_t structure, and the logging
 * subsystem will pick out the elements within the hse_err_t structure and
 * format them in the text log file as well as store them as structured data
 * in the data log file.
 *
 * Currently, knowledge of what format specifiers are valid and the definition
 * of the associated formatting routines is contained with logging.c. To log
 * a structure defined in the KVS component, logging.c has to include code
 * from KVS.
 *
 * There needs to be a way that clients of the HSE platform logging subsystem
 * can register conversion specifiers and their associated routines.
 */

#ifdef HSE_RELEASE_BUILD
#define HSE_LOG_SQUELCH_NS_DEFAULT (1000 * 1000)
#else
#define HSE_LOG_SQUELCH_NS_DEFAULT (0)
#endif

#define log_pri(_pri, _fmt, _async, _argv, ...)                                               \
    do {                                                                                      \
        static struct event_counter hse_ev_log _dt_section = {                                \
            .ev_odometer = 0,                                                                 \
            .ev_pri = (_pri),                                                                 \
            .ev_flags = EV_FLAGS_HSE_LOG,                                                     \
            .ev_file = __FILE__,                                                              \
            .ev_line = __LINE__,                                                              \
            .ev_dte = {                                                                       \
                .dte_data = &hse_ev_log,                                                      \
                .dte_ops = &event_counter_ops,                                                \
                .dte_type = DT_TYPE_ERROR_COUNTER,                                            \
                .dte_line = __LINE__,                                                         \
                .dte_file = __FILE__,                                                         \
                .dte_func = __func__,                                                         \
            }                                                                                 \
        };                                                                                    \
                                                                                              \
        hse_log(&hse_ev_log, (_fmt), (_async),                                                \
            LOG_DOMAIN ? LOG_DOMAIN : log_domain_basename(__FILE__), (_argv), ##__VA_ARGS__); \
    } while (0)


/* Main logging APIs for HSE.  Debug, info and warn levels use async
 * logging. Err and crit levels use synchronous logging.
 */
#define log_debug(_fmt, ...)    log_pri(HSE_LOGPRI_DEBUG, (_fmt), true, NULL, ##__VA_ARGS__)
#define log_info(_fmt, ...)     log_pri(HSE_LOGPRI_INFO, (_fmt), true, NULL, ##__VA_ARGS__)
#define log_warn(_fmt, ...)     log_pri(HSE_LOGPRI_WARN, (_fmt), true, NULL, ##__VA_ARGS__)
#define log_err(_fmt, ...)      log_pri(HSE_LOGPRI_ERR, (_fmt), false, NULL, ##__VA_ARGS__)
#define log_crit(_fmt, ...)     log_pri(HSE_LOGPRI_CRIT, (_fmt), false, NULL, ##__VA_ARGS__)

/* A special API used in hse_init to synchronously log info level messages
 */
#define log_info_sync(_fmt, ...) log_pri(HSE_LOGPRI_INFO, (_fmt), false, NULL, ##__VA_ARGS__)

/* Emit logs with pretty printed merr_t values
 */
#define log_prix(_pri, _fmt, _async, _err, ...)               \
    do {                                                      \
        void *av[] = { &(_err), NULL };                       \
                                                              \
        log_pri((_pri), (_fmt), (_async), av, ##__VA_ARGS__); \
    } while (0)

#define log_warnx(_fmt, _err, ...)  log_prix(HSE_LOGPRI_WARN, (_fmt), true, (_err), ##__VA_ARGS__)
#define log_errx(_fmt, _err, ...)   log_prix(HSE_LOGPRI_ERR, (_fmt), false, (_err), ##__VA_ARGS__)


/* Helper APIs used by above log macros.  Not intended to be called directly.
 */
void
hse_log(
    struct event_counter *ev,
    const char *fmt,
    bool async,
    const char *domain,
    void **args,
    ...) HSE_PRINTF(2, 6);

/* Convert a log priority level: numeric to string.
 */
const char *
hse_logpri_val_to_name(hse_logpri_t val);

/* Convert a log priority level: string to numeric.
 */
hse_logpri_t
hse_logpri_name_to_val(const char *name);

/* Support for custom "printf" format specifier such as "@@e" (for
 * pretty printing merr_t values).
 */
struct hse_log_fmt_state;

typedef bool
hse_log_fmt_func_t(char **pos, char *end, void *obj);

typedef bool
hse_log_add_func_t(struct hse_log_fmt_state *state, void *obj);

bool
hse_log_register(int code, hse_log_fmt_func_t *fmt, hse_log_add_func_t *add);

bool
hse_log_deregister(int code);

bool
hse_log_push(struct hse_log_fmt_state *state, bool indexed, const char *name, const char *value);

/* Public APIs for structured logging
 */
#define slog_debug(...)     slog_internal(HSE_LOGPRI_DEBUG, LOG_DOMAIN ? LOG_DOMAIN : \
    log_domain_basename(__FILE__), __VA_ARGS__, NULL)
#define slog_info(...)      slog_internal(HSE_LOGPRI_INFO, LOG_DOMAIN ? LOG_DOMAIN : \
    log_domain_basename(__FILE__), __VA_ARGS__, NULL)
#define slog_warn(...)      slog_internal(HSE_LOGPRI_WARN, LOG_DOMAIN ? LOG_DOMAIN : \
    log_domain_basename(__FILE__), __VA_ARGS__, NULL)
#define slog_err(...)       slog_internal(HSE_LOGPRI_ERR, LOG_DOMAIN ? LOG_DOMAIN : \
    log_domain_basename(__FILE__), __VA_ARGS__, NULL)

#define SLOG_START(type) \
    slog_internal_validate(SLOG_TOKEN_START, "%s", (type)), SLOG_TYPE_IDENTIFIER, "%s", (type)

#define SLOG_FIELD(key, fmt, val) \
    slog_internal_validate(SLOG_TOKEN_FIELD, (fmt), (val)), (key), (fmt), (val)

#define SLOG_END SLOG_TOKEN_END


/* Structured logging internals
 */

enum slog_token {
    SLOG_TOKEN_START = 1,
    SLOG_TOKEN_FIELD,
    SLOG_TOKEN_END
};

void
slog_internal(hse_logpri_t priority, const char *domain, ...);

/* A helper function that tricks compiler into validating printf specifiers */
static inline int HSE_PRINTF(2, 3)
slog_internal_validate(enum slog_token tok, char *fmt, ...)
{
    return tok;
}

/* clang-format on */

#endif /* HSE_PLATFORM_LOGGING_H */
