/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdbool.h>
#include <stdio.h>
#include <syslog.h>

#include <hse_util/event_counter.h>
#include <hse_util/minmax.h>
#include <hse_util/mutex.h>

#include <hse/logging/logging.h>

#ifdef HSE_REL_SRC_DIR
#define SRC_FILE (__FILE__ + sizeof(HSE_REL_SRC_DIR) + 1)
#else
#define SRC_FILE __FILE__
#endif

static int log_level;
static FILE *log_file;
static uint64_t log_squelch_ns;
static bool logging_initialized;
static thread_local char scratch_buffer[1024];

merr_t
logging_init(const struct logging_params *const params)
{
    FILE *fp = NULL;

    if (!params)
        return merr(EINVAL);

    if (!params->lp_enabled)
        return 0;

    if (params->lp_level < LOG_EMERG || params->lp_level > LOG_DEBUG)
        return merr(EINVAL);

    if (params->lp_destination == LOG_DEST_STDOUT) {
        fp = stdout;
    } else if (params->lp_destination == LOG_DEST_STDERR) {
        fp = stderr;
    } else if (params->lp_destination == LOG_DEST_FILE) {
        fp = fopen(params->lp_path, "a");
        if (!fp) {
            char buf[256];
            const merr_t err = merr(errno);

            merr_strinfo(err, buf, sizeof(buf), NULL);

            fprintf(stderr, "[HSE] %s:%d %s: failed to open log file (%s): %s",
                SRC_FILE, __LINE__, __func__, params->lp_path, buf);
            return err;
        }

        setlinebuf(fp);
    } else {
        if (params->lp_destination != LOG_DEST_SYSLOG)
            return merr(EINVAL);
    }

    if (!logging_initialized) {
        logging_initialized = true;
        log_file = fp;
        log_level = params->lp_level;
        log_squelch_ns = params->lp_squelch_ns;
    }

    return 0;
}

void
logging_fini(void)
{
    if (log_file && log_file != stdout && log_file != stderr)
        fclose(log_file);
    log_file = NULL;

    logging_initialized = false;
}

void
log_impl(
    struct event_counter *ev, /* contains call site info and pri     */
    merr_t err,               /* error value                         */
    const char *fmt,          /* the platform-specific format string */
    ...)                      /* variable-length argument list       */
{
    int rc;
    va_list args;
    uint64_t now;

    if (ev->ev_pri > log_level)
        return;

    event_counter(ev);

    now = get_time_ns();
    if (now < ev->ev_priv)
        return;

    ev->ev_priv = now + log_squelch_ns;

    if (err) {
        char buf[256];

        merr_strerror(err, buf, sizeof(buf));

        rc = snprintf(scratch_buffer, sizeof(scratch_buffer), "[HSE] %s:%d %s: %s: %s",
            ev->ev_file, ev->ev_line, ev->ev_dte.dte_func, fmt, buf);
    } else {
        rc = snprintf(scratch_buffer, sizeof(scratch_buffer), "[HSE] %s:%d %s: %s",
            ev->ev_file, ev->ev_line, ev->ev_dte.dte_func, fmt);
    }
    if (rc >= sizeof(scratch_buffer)) {
        if (log_file) {
            fprintf(log_file, "[HSE] %s:%d %s: scatch buffer size too small, needed %d for \"%s\"",
                SRC_FILE, __LINE__, __func__, rc, scratch_buffer);
        } else {
            syslog(LOG_ERR, "[HSE] %s:%d %s: scatch buffer size too small, needed %d for \"%s\"",
                SRC_FILE, __LINE__, __func__, rc, scratch_buffer);
        }

        return;
    } else if (rc < 0) {
        if (log_file) {
            fprintf(log_file, "[HSE] %s:%d %s: bad printf format string: %s",
                SRC_FILE, __LINE__, __func__, fmt);
        } else {
            syslog(LOG_ERR, "[HSE] %s:%d %s: bad printf format string: %s",
                SRC_FILE, __LINE__, __func__, fmt);
        }

        return;
    }

    va_start(args, fmt);
    if (log_file) {
        vfprintf(log_file, scratch_buffer, args);
    } else {
        vsyslog(ev->ev_pri, scratch_buffer, args);
    }
    va_end(args);
}

const char *
log_priority_to_string(int prio)
{
    static const char *namev[] = {
        "EMERG", "ALERT", "CRIT", "ERR", "WARNING", "NOTICE", "INFO", "DEBUG"
    };

    prio = clamp_t(int, prio, 0, NELEM(namev) - 1);

    return namev[prio];
}

int
log_priority_from_string(const char *name)
{
    static const char *list = "EMERG   ALERT   CRIT    ERR     WARNING NOTICE  INFO    DEBUG   ";

    name = strcasestr(list, name);
    if (name)
        return (name - list) / 8;

    return LOG_DEBUG;
}
