/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/logging.h>
#include <hse_util/time.h>
#include <hse_util/data_tree.h>
#include <hse_util/event_counter.h>

void
ev_get_timestamp(atomic_ulong *timestamp)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    atomic_set(timestamp, (tv.tv_sec * USEC_PER_SEC) + tv.tv_usec);
}

size_t
snprintf_timestamp(char *buf, size_t buf_sz, atomic_ulong *timestamp)
{
    struct timeval tv;
    size_t         ret;
    u64            t = atomic_read(timestamp);
    struct tm      tm;

    tv.tv_sec = t / USEC_PER_SEC;
    tv.tv_usec = t % USEC_PER_SEC;

    gmtime_r(&tv.tv_sec, &tm);

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
    struct event_counter *ec = dte->dte_data;

    if (!strcmp(field, "source")) {
        if (!strcmp(value, "all")) {
            return true;
        } else if (ec->ev_flags & EV_FLAGS_HSE_LOG) {
            if (!strcmp("hse_log", value))
                return true;
        } else {
            if (!strcmp("events", value))
                return true;
        }
    } else if (!strcmp(field, "ev_pri")) {
        hse_logpri_t pri = hse_logpri_name_to_val(value);

        if (ec->ev_pri <= pri)
            return true;
    }
    return false;
}

static size_t
ev_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp)
{
    struct event_counter *ec = dte->dte_data;

    switch (dsp->field) {
        case DT_FIELD_PRIORITY:
            ec->ev_pri = hse_logpri_name_to_val(dsp->value);
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
 *       priority: INFO
 *
 * Fields are indented 6 spaces.
 */
static size_t
ev_emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    struct event_counter *ec = dte->dte_data;
    char                  value[128];
    ulong                 odometer;

    yaml_start_element(yc, "path", dte->dte_path);

    snprintf(value, sizeof(value), "%s", hse_logpri_val_to_name(ec->ev_pri));
    yaml_element_field(yc, "level", value);

    odometer = atomic_read(&ec->ev_odometer);
    u64_to_string(value, sizeof(value), odometer);
    yaml_element_field(yc, "odometer", value);

    snprintf_timestamp(value, sizeof(value), &ec->ev_odometer_timestamp);
    yaml_element_field(yc, "odometer timestamp", value);

    if (ec->ev_trip_odometer != 0) {
        u64_to_string(value, sizeof(value), odometer - ec->ev_trip_odometer);
        yaml_element_field(yc, "trip odometer", value);

        snprintf_timestamp(value, sizeof(value), &ec->ev_trip_odometer_timestamp);
        yaml_element_field(yc, "trip odometer timestamp", value);
    }

    if (ec->ev_flags & EV_FLAGS_HSE_LOG)
        yaml_element_field(yc, "source", "hse_log");
    else
        yaml_element_field(yc, "source", "events");

    yaml_end_element(yc);

    return 1;
}

struct dt_element_ops event_counter_ops = {
    .dto_emit = ev_emit_handler,
    .dto_set = ev_set_handler,
    .dto_match_selector = ev_match_select_handler,
};

bool
ev_root_match_select_handler(struct dt_element *dte, char *field, char *value)
{
    return true;
}

static size_t
ev_root_emit_handler(struct dt_element *dte, struct yaml_context *yc)
{
    yaml_start_element_type(yc, basename(dte->dte_path));

    return 1;
}

static struct dt_element_ops event_counter_root_ops = {
    .dto_emit = ev_root_emit_handler,
    .dto_match_selector = ev_root_match_select_handler,
};

/* Install the root node for event counters. This is important because we
 * need to identify it as a ROOT node to get the write emit() behavior.
 */
void
event_counter_init(void)
{
    static struct dt_element hse_dte_event = {
        .dte_ops = &event_counter_root_ops,
        .dte_type = DT_TYPE_ROOT,
        .dte_file = __FILE__,
        .dte_line = __LINE__,
        .dte_func = __func__,
        .dte_path = DT_PATH_EVENT,
    };

    dt_add(&hse_dte_event);
}

void
event_counter(struct event_counter *ec)
{
    if (HSE_UNLIKELY(1 == atomic_inc_return(&ec->ev_odometer))) {
        struct dt_element *dte = &ec->ev_dte;

        snprintf(dte->dte_path, sizeof(dte->dte_path), "%s/%s/%s/%d",
                 DT_PATH_EVENT, basename(dte->dte_file), dte->dte_func, dte->dte_line);

        dt_add(dte);
    }

    if (!(ec->ev_flags & EV_FLAGS_NOTIME))
        ev_get_timestamp(&ec->ev_odometer_timestamp);
}
