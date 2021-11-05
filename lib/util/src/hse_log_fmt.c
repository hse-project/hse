/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>

#include "logging_impl.h"
#include "logging_util.h"

/**
 * Config
 */

merr_t
show_timestamp_nsec(char *str, size_t strsz, void *val)
{
    snprintf(str, strsz, "%lu", (unsigned long)((u64)1000 * *(u64 *)val));
    return 0;
}

/**
 * Event Counters
 */

static bool
fmt_event_counter_stats(char **tgt_pos, char *tgt_end, void *obj)
{
    bool                  res = true;
    struct event_counter *ev = (struct event_counter *)obj;

    int   written;
    char *tgt = *tgt_pos;
    int   space = (int)(tgt_end - *tgt_pos);
    char  value[100];

    snprintf(value, sizeof(value), "%d", atomic_read(&ev->ev_odometer));
    written = snprintf(tgt, space, "[EV] %s: %s", ev->ev_dte.dte_path, value);

    if (written >= 0) {
        tgt += (written > space) ? space : written;
        *tgt_pos = tgt;
        res = (written < space);
    }

    return res;
}

static bool
add_event_counter_stats(struct hse_log_fmt_state *state, void *obj)
{
    struct event_counter *ev = (struct event_counter *)obj;

    bool               res = true;
    static const char *cat = "hse_%d_category";
    static const char *cat_val = "events";
    static const char *ver = "hse_%d_version";
    static const char *ver_val = "0";

    /* Names */
    static const char *n_path = "hse_%d_path";
    static const char *n_odometer = "hse_%d_odometer";
    static const char *n_trip_odometer = "hse_%d_trip_odometer";
    static const char *n_flags = "hse_%d_flags";
    static const char *n_timestamp = "hse_%d_timestamp";

    /* Values */
    char *v_path = ev->ev_dte.dte_path + strlen(DT_PATH_EVENT);
    char  v_odometer[100];
    char  v_trip_odometer[100];
    char  v_flags[100];
    char  v_timestamp[100];
    u64   ts;

    snprintf(v_odometer, sizeof(v_odometer), "%d", atomic_read(&ev->ev_odometer));
    snprintf(v_trip_odometer, sizeof(v_trip_odometer), "%d", ev->ev_trip_odometer);
    snprintf(v_flags, sizeof(v_flags), "0x%x", ev->ev_flags);

    ts = atomic_read(&ev->ev_odometer_timestamp);
    show_timestamp_nsec(v_timestamp, sizeof(v_timestamp), &ts);

    res =
        (push_nv(state, true, cat, cat_val) && push_nv(state, true, ver, ver_val) &&
         push_nv(state, true, n_path, v_path) && push_nv(state, true, n_odometer, v_odometer) &&
         push_nv(state, true, n_trip_odometer, v_trip_odometer) &&
         push_nv(state, true, n_flags, v_flags) && push_nv(state, true, n_timestamp, v_timestamp));

    return res;
}

/******************************************************************************
 * Family of functions to take various data structures and either format
 * them into an intermediate format string or append their key elements to
 * the accumulating structured data.
 ******************************************************************************/

bool
fmt_hse_err(char **tgt_pos, char *tgt_end, void *obj)
{
    struct merr_info info;
    merr_t           err = *(merr_t *)obj;
    char *           tgt = *tgt_pos;
    int              space = (int)(tgt_end - *tgt_pos);
    int              written;
    bool             res = false;

    written = snprintf(tgt, space, "%s", merr_info(err, &info));
    if (written >= 0) {
        tgt += (written > space) ? space : written;
        *tgt_pos = tgt;
        res = (written < space);
    }
    return res;
}

bool
add_hse_err(struct hse_log_fmt_state *state, void *obj)
{
    static const char *cat = "hse_%d_category";
    static const char *cat_val = "hse_error";
    static const char *ver = "hse_%d_version";
    static const char *ver_val = "0";
    static const char *code = "hse_%d_code";
    static const char *file = "hse_%d_file";
    static const char *line = "hse_%d_line";
    static const char *desc = "hse_%d_description";

    merr_t      err = *(merr_t *)obj;
    char        err_code[12]; /* large enough for a 32-bit int w/ null */
    const char *src_file;
    char        err_file[MERR_INFO_SZ];
    char        err_line[12]; /* large enough for a 32-bit int w/ null */
    char        err_desc[300];
    bool        res;

    src_file = merr_file(err);

    snprintf(err_code, sizeof(err_code), "%d", merr_errno(err));
    snprintf(err_file, sizeof(err_file), "%s", src_file);
    snprintf(err_line, sizeof(err_line), "%d", merr_lineno(err));
    merr_strerror(err, err_desc, sizeof(err_desc));

    res =
        (push_nv(state, true, cat, cat_val) && push_nv(state, true, ver, ver_val) &&
         push_nv(state, true, code, err_code) && push_nv(state, true, file, err_file) &&
         push_nv(state, true, line, err_line) && push_nv(state, true, desc, err_desc));

    return res;
}

/* --------------------------------------------------
 * Register these with hse_log().
 */

void
hse_log_reg_platform(void)
{
    hse_log_register('E', fmt_event_counter_stats, add_event_counter_stats);
    if (!hse_log_register('e', fmt_hse_err, add_hse_err))
        backstop_log("init_hse_logging() cannot add hse_err formatter");
}
