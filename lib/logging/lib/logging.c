/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>

#include <hse/error/merr.h>
#include <hse/logging/logging.h>
#include <hse/util/minmax.h>
#include <hse/util/timer.h>

/* The log_xxx() APIs are allowed to be used prior to calling logging_init().
 * In practice, this only includes code that deals with hse_gparams. That code
 * includes error and debug statements. Ideally, we want to ignore debug logs in
 * those sections, and only report useful information like errors to the user.
 * By making the default log level INFO, we can easily achieve this without more
 * intrusive solutions. Note that once logging_init() is called, the log level
 * will change to whatever is specified by hse_gparams.
 */
static int log_level = LOG_INFO;

static FILE *log_file;
static bool logging_initialized;
static bool logging_enabled = true;
static merr_stringify *log_err_ctx_stringify;
static thread_local char log_buffer_tls[1024];
static uint64_t log_squelch_ns = LOG_SQUELCH_NS_DEFAULT;

static void HSE_PRINTF(2, 3)
backstop(const int level, const char * const fmt, ...)
{
    va_list args;

    va_start(args, fmt);

    if (log_file) {
        vfprintf(log_file, fmt, args);
    } else {
        vsyslog(level, fmt, args);
    }

    va_end(args);
}

merr_t
logging_init(const struct logging_params * const params, merr_stringify * const ctx_stringify)
{
    FILE *fp = NULL;

    if (!params)
        return merr(EINVAL);

    if (params->lp_level < LOG_EMERG || params->lp_level > LOG_DEBUG)
        return merr(EINVAL);

    logging_enabled = params->lp_enabled;
    if (!logging_enabled)
        return 0;

    switch (params->lp_destination) {
    case LOG_DEST_STDOUT:
        fp = stdout;
        break;
    case LOG_DEST_STDERR:
        fp = stderr;
        break;
    case LOG_DEST_FILE:
        fp = fopen(params->lp_path, "a");
        if (!fp) {
            char buf[256];
            const merr_t err = merr(errno);

            merr_strinfo(err, buf, sizeof(buf), NULL, NULL);

            fprintf(
                stderr, "[HSE] %s:%d %s: failed to open log file (%s): %s\n", REL_FILE(__FILE__),
                __LINE__, __func__, params->lp_path, buf);
            return err;
        }

        setlinebuf(fp);
    case LOG_DEST_SYSLOG:
        break;
    default:
        return merr(EINVAL);
    }

    if (!logging_initialized) {
        log_file = fp;
        log_level = params->lp_level;
        log_err_ctx_stringify = ctx_stringify;
        log_squelch_ns = params->lp_squelch_ns;
        logging_initialized = true;
    }

    return 0;
}

void
logging_fini(void)
{
    if (log_file && log_file != stdout && log_file != stderr)
        fclose(log_file);
    log_file = NULL;
    log_level = LOG_INFO;
    log_err_ctx_stringify = NULL;
    log_squelch_ns = LOG_SQUELCH_NS_DEFAULT;
    logging_enabled = true;
    logging_initialized = false;
}

void
log_impl(
    const int level,         /* log level                     */
    const char * const file, /* file                          */
    const int lineno,        /* line number                   */
    const char * const func, /* function name                 */
    uint64_t * const timer,  /* timer                         */
    const merr_t err,        /* error value                   */
    const char * const fmt,  /* format string                 */
    ...)                     /* variable-length argument list */
{
    int rc;
    va_list args;
    uint64_t now;
    FILE *output;

    if (!logging_enabled || level > log_level)
        return;

    if (!logging_initialized) {
        output = level <= LOG_WARNING ? stderr : stdout;
    } else {
        output = log_file;
    }

    now = get_time_ns();
    if (now < *timer)
        return;

    *timer = now + log_squelch_ns;

    if (err) {
        char buf[256];
        size_t needed_sz HSE_MAYBE_UNUSED;

        merr_strinfo(err, buf, sizeof(buf), log_err_ctx_stringify, &needed_sz);
        assert(needed_sz < sizeof(buf));

        rc = snprintf(
            log_buffer_tls, sizeof(log_buffer_tls), "[HSE] %s:%d: %s: %s: %s\n", file, lineno, func,
            fmt, buf);
    } else {
        rc = snprintf(
            log_buffer_tls, sizeof(log_buffer_tls), "[HSE] %s:%d: %s: %s\n", file, lineno, func,
            fmt);
    }
    if (rc >= sizeof(log_buffer_tls)) {
        backstop(
            LOG_ERR, "[HSE] %s:%d: %s: scatch buffer size too small, needed %d for %s:%d\n",
            REL_FILE(__FILE__), __LINE__ - 1, __func__, rc, file, lineno);
    } else if (rc < 0) {
        backstop(
            LOG_ERR, "[HSE] %s:%d: %s: bad format string from %s:%d\n", REL_FILE(__FILE__),
            __LINE__ - 1, __func__, file, lineno);

        return;
    }

    va_start(args, fmt);

    if (output) {
        vfprintf(output, log_buffer_tls, args);
    } else {
        vsyslog(level, log_buffer_tls, args);
    }

    va_end(args);
}

const char *
log_level_to_string(int level)
{
    static const char *namev[] = { "EMERG",   "ALERT",  "CRIT", "ERR",
                                   "WARNING", "NOTICE", "INFO", "DEBUG" };

    level = clamp_t(int, level, 0, NELEM(namev) - 1);

    return namev[level];
}

int
log_level_from_string(const char *name)
{
    static const char *list = "EMERG   ALERT   CRIT    ERR     WARNING NOTICE  INFO    DEBUG   ";

    name = strcasestr(list, name);
    if (name)
        return (int)((uintptr_t)name - (uintptr_t)list) / 8;

    return LOG_DEBUG;
}
