/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_LOGGING_H
#define HSE_PLATFORM_LOGGING_H

#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>
#include <hse_util/data_tree.h>
#include <hse_util/event_counter.h>
#include <hse_util/timing.h>
#include <hse_util/logging_types.h>
#include <hse_ikvdb/hse_gparams.h>

#include <syslog.h>

/* clang-format off */

#ifndef HSE_LOG_PRI_DEFAULT
#define HSE_LOG_PRI_DEFAULT (7)
#endif

#define HSE_MARK            "[HSE] "
#define HSE_EMERG           HSE_EMERG_VAL, HSE_MARK
#define HSE_ALERT           HSE_ALERT_VAL, HSE_MARK
#define HSE_CRIT            HSE_CRIT_VAL, HSE_MARK
#define HSE_ERR             HSE_ERR_VAL, HSE_MARK
#define HSE_WARNING         HSE_WARNING_VAL, HSE_MARK
#define HSE_NOTICE          HSE_NOTICE_VAL, HSE_MARK
#define HSE_INFO            HSE_INFO_VAL, HSE_MARK
#define HSE_DEBUG           HSE_DEBUG_VAL, HSE_MARK

/*
 * A single log instance can have no more than MAX_HSE_SPECS hse-specific
 * conversion specifiers. For that instance there can be no more than
 * MAX_HSE_NV_PAIRS of structured log data entries created.
 *
 * As structured name value data is accumulated it must be retained
 * until right before the dynamic call to json payload formatter so that
 * those values can be tacked onto its argument list.
 */
#define MAX_HSE_SPECS       (10)

/*
 * A single log instance can have no more than MAX_HSE_NV_PAIRS of structured
 * log data entries created.
 *
 * The need for the space is due to current logging logic that requies the
 * data to be accumulated and passed as a argument to json formatter to
 * generate a json formated payload which is passed as a final argument
 * to syslog in user space or printk_emit in case of kernel.
 * As structured name value data is accumulated it must be retained until
 * those values can be tacked onto its argument list.
 */
#define MAX_HSE_NV_PAIRS    (40 * MAX_HSE_SPECS)

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

/* hse_log_pri() is not intended to be used externally, it exists
 * only to decode the priority value from the HSE_* definitions.
 */
#define hse_log_pri(pri, fmt, async, hse_args, ...)                     \
    do {                                                                \
        static struct event_counter hse_ev_log _dt_section = {          \
            .ev_odometer = ATOMIC_INIT(0),                              \
            .ev_pri = pri,                                              \
            .ev_flags = EV_FLAGS_HSE_LOG,                               \
            .ev_file = __FILE__,                                        \
            .ev_line = __LINE__,                                        \
            .ev_dte = {                                                 \
                .dte_data = &hse_ev_log,                                \
                .dte_ops = &event_counter_ops,                          \
                .dte_type = DT_TYPE_ERROR_COUNTER,                      \
                .dte_line = __LINE__,                                   \
                .dte_file = __FILE__,                                   \
                .dte_func = __func__,                                   \
            },                                                          \
        };                                                              \
                                                                        \
        _hse_log(&hse_ev_log, (fmt), (async), (hse_args), ##__VA_ARGS__); \
    } while (0)


#define hse_log(log_fmt, ...) hse_log_pri(log_fmt, true, NULL, ##__VA_ARGS__)

/* Asynchronous logging. Can be used from interrupt context. */
#define hse_alog(log_fmt, ...) hse_log_pri(log_fmt, true, NULL, ##__VA_ARGS__)

#define hse_xlog(log_fmt, hse_args, ...) hse_log_pri(log_fmt, true, hse_args, ##__VA_ARGS__)

#define hse_elog(log_fmt, err, ...)                    \
    do {                                               \
        void *av[] = { &err, 0 };                      \
        hse_log_pri(log_fmt, true, av, ##__VA_ARGS__); \
    } while (0)

#define hse_log_sync(log_fmt, ...) hse_log_pri(log_fmt, false, NULL, ##__VA_ARGS__)

void
_hse_log(struct event_counter *ev, const char *fmt, bool async, void **args, ...) HSE_PRINTF(2, 5);

const char *
hse_logprio_val_to_name(int priority);

log_priority_t
hse_logprio_name_to_val(const char *priority);

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

struct slog;

enum slog_token {
    _SLOG_START_TOKEN = 1,
    _SLOG_CHILD_START_TOKEN,
    _SLOG_FIELD_TOKEN,
    _SLOG_LIST_TOKEN,
    _SLOG_CHILD_END_TOKEN,
    _SLOG_END_TOKEN
};

#define HSE_SLOG_START(type) NULL, _SLOG_START_TOKEN, "type", "%s", (type)
#define HSE_SLOG_CHILD_START(key) _SLOG_CHILD_START_TOKEN, (key)
#define HSE_SLOG_CHILD_END _SLOG_CHILD_END_TOKEN
#define HSE_SLOG_END _SLOG_END_TOKEN

#define HSE_SLOG_FIELD(key, fmt, val) hse_slog_validate_field(fmt, val), (key), (fmt), (val)

#define HSE_SLOG_LIST(key, fmt, cnt, val) \
    hse_slog_validate_list(fmt, val[0]), (key), (fmt), (cnt), (val)

#define hse_slog_pri(pri, fmt, ...) hse_slog_internal((pri), __VA_ARGS__)
#define hse_slog(log_fmt, ...) hse_slog_pri(log_fmt, __VA_ARGS__, NULL)

#define hse_slog_append(logger, ...) hse_slog_append_internal((logger), __VA_ARGS__, NULL)

void
hse_slog_internal(int priority, const char *fmt, ...);

int
hse_slog_create(int priority, const char *unused, struct slog **sl, const char *type);

int
hse_slog_append_internal(struct slog *sl, ...);

int
hse_slog_commit(struct slog *sl);

static inline HSE_PRINTF(1, 2) int hse_slog_validate_field(char *fmt, ...)
{
    return _SLOG_FIELD_TOKEN;
}

static inline HSE_PRINTF(1, 2) int hse_slog_validate_list(char *fmt, ...)
{
    return _SLOG_LIST_TOKEN;
}

extern FILE *logging_file;

#endif /* HSE_PLATFORM_LOGGING_H */
