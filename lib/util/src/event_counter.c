/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define NO_ERROR_COUNTER

#include <hse_util/platform.h>
#include <hse_util/logging.h>

#include <hse_util/data_tree.h>
#include <hse_util/event_counter.h>
#include <hse_util/time.h>

void
ev_get_timestamp(atomic64_t *timestamp)
{
    u64 t;

    t = ktime_get_real();
    atomic64_set(timestamp, t);
}

size_t
snprintf_timestamp(char *buf, size_t buf_sz, atomic64_t *timestamp)
{
    struct timeval tv;
    size_t         ret;
    u64            t = atomic64_read(timestamp);
    struct tm      tm;

    tv.tv_sec = t / USEC_PER_SEC;
    tv.tv_usec = t % USEC_PER_SEC;

    time_to_tm(tv.tv_sec, 0, &tm);

    ret = snprintf(
        buf,
        buf_sz,
        "%04ld-%02d-%02d %02d:%02d:%02d.%03ld",
        (long)(tm.tm_year + 1900),
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tv.tv_usec);

    return ret;
}

bool
ev_match_select_handler(struct dt_element *dte, char *field, char *value)
{
    struct event_counter *ec = (struct event_counter *)dte->dte_data;

    if (!strcmp(field, "source")) {
        if (!strcmp(value, "all")) {
            return true;
        } else if (ec->ev_flags & EV_FLAGS_HSE_LOG) {
            if (!strcmp("hse_log", value))
                return true;
        } else {
            if (!strcmp("event_counter", value))
                return true;
        }
    } else if (!strcmp(field, "ev_log_level")) {
        log_priority_t pri = hse_logprio_name_to_val(value);

        if (ec->ev_log_level <= pri)
            return true;
    }
    return false;
}

static size_t
set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct event_counter *ec = dte->dte_data;

    switch (dsp->field) {
        case DT_FIELD_PRIORITY:
            ec->ev_log_level = hse_logprio_name_to_val(dsp->value);
            break;

        case DT_FIELD_TRIP_ODOMETER:
            ec->ev_trip_odometer = atomic_read(&ec->ev_odometer);
            ev_get_timestamp(&ec->ev_trip_odometer_timestamp);
            break;

        case DT_FIELD_CLEAR:
        case DT_FIELD_ODOMETER_TIMESTAMP:
        case DT_FIELD_TRIP_ODOMETER_TIMESTAMP:
        case DT_FIELD_ODOMETER:
        case DT_FIELD_INVALID:
        default:
            return 0;
    };

    return 1;
}

/**
 * emit_handler output fits into a YAML document. spacing is driven by
 * YAML context.
 *
 * An event_counter (with its preceding data and event_counter elements
 * looks like this:
 * data:
 *   - event_counter:
 *     - path: /data/event_counter/ev_emit/event_counter_test.c/ev_emit/495
 *       odometer: 1
 *       odometer timestamp: 1463576343.291465
 *       trip odometer: 1
 *       trip odometer timestamp: 0.0
 *       priority: HSE_INFO
 *
 * Fields are indented 6 spaces.
 */
static size_t
emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    struct event_counter *ec = (struct event_counter *)dte->dte_data;
    char                  value[DT_PATH_LEN];
    int                   odometer_val = atomic_read(&ec->ev_odometer);

    yaml_start_element(yc, "path", dte->dte_path);

    snprintf(value, DT_PATH_LEN, "%s", hse_logprio_val_to_name(ec->ev_log_level));
    yaml_element_field(yc, "level", value);

    snprintf(value, DT_PATH_LEN, "%d", odometer_val);
    yaml_element_field(yc, "odometer", value);

    snprintf_timestamp(value, DT_PATH_LEN, &ec->ev_odometer_timestamp);
    yaml_element_field(yc, "odometer timestamp", value);

    if (ec->ev_trip_odometer != 0) {
        snprintf(value, DT_PATH_LEN, "%d", odometer_val - ec->ev_trip_odometer);
        yaml_element_field(yc, "trip odometer", value);

        snprintf_timestamp(value, DT_PATH_LEN, &ec->ev_trip_odometer_timestamp);
        yaml_element_field(yc, "trip odometer timestamp", value);
    }

    if (ec->ev_flags & EV_FLAGS_HSE_LOG)
        yaml_element_field(yc, "source", "hse_log");
    else
        yaml_element_field(yc, "source", "event_counter");

    yaml_end_element(yc);

    return 1;
}

static size_t
log_handler(struct dt_element *dte, int log_level)
{

    struct event_counter *ev = (struct event_counter *)dte->dte_data;
    void *                av[] = { ev, 0 };

    /* [HSE_REVISIT] Do we use this logging feature anywhere?
     */
    hse_xlog(HSE_INFO "@@E", av);

    return 1;
}

static size_t
count_handler(struct dt_element *element)
{
    return 1;
}

struct dt_element_ops event_counter_ops = {
    .emit = emit_handler,
    .log = log_handler,
    .set = set_handler,
    .count = count_handler,
    .match_selector = ev_match_select_handler,
};

const char *
ev_pathname(const char *path)
{
    const char *ptr;

    ptr = strrchr(path, '/');

    return ptr ? ptr + 1 : path;
}

bool
ev_root_match_select_handler(struct dt_element *dte, char *field, char *value)
{
    return true;
}

static size_t
root_emit_handler(struct dt_element *me, struct yaml_context *yc)
{
    yaml_start_element_type(yc, "event_counter");

    return 1;
}

static size_t
root_remove_handler(struct dt_element *element)
{
    /* Whole of data_tree must have been removed...*/
    struct event_counter *ec = element->dte_data;

    atomic_set(&ec->ev_odometer, 0);
    return 0;
}

static struct dt_element_ops event_counter_root_ops = {
    .emit = root_emit_handler,
    .remove = root_remove_handler,
    .match_selector = ev_root_match_select_handler,
};

/* Install the root node for event counters. This is important because we
 * need to identify it as a ROOT node to get the write emit() behavior.
 */

void
event_counter_init(void)
{
    static struct event_counter ec = {
        .ev_odometer = ATOMIC_INIT(0),
    };
    static struct dt_element dte = {
        .dte_data = &ec,
        .dte_ops = &event_counter_root_ops,
        .dte_type = DT_TYPE_ROOT,
        .dte_path = "/data/event_counter",
    };
    dt_add(dt_data_tree, &dte);
}

void
event_counter(struct dt_element *dte, struct event_counter *ec)
{
    if (HSE_UNLIKELY(1 == atomic_inc_return(&ec->ev_odometer))) {
        snprintf(
            dte->dte_path,
            DT_PATH_LEN,
            "/data/event_counter/%s/%s/%s/%d",
            dte->dte_comp,
            ev_pathname(dte->dte_file),
            dte->dte_func,
            dte->dte_line);
        dt_add(dt_data_tree, dte);
        ec->ev_dte = dte;
    }
    ev_get_timestamp(&ec->ev_odometer_timestamp);
}
