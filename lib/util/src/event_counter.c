/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/logging/logging.h>
#include <hse_util/assert.h>
#include <hse_util/platform.h>
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
        "%04ld-%02d-%02dT%02d:%02d:%02d.%03ld",
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

    if (!strcmp(field, "level")) {
        const int level = log_level_from_string(value);

        if (ec->ev_level <= level)
            return true;
    }

    return false;
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
ev_emit_handler(struct dt_element *const dte, cJSON *const root)
{
    char value[128];
    cJSON *elem = cJSON_CreateObject();
    struct event_counter *ec = dte->dte_data;
    const unsigned long odometer = atomic_read(&ec->ev_odometer);

    INVARIANT(dte);
    INVARIANT(cJSON_IsArray(root));

    cJSON_AddStringToObject(elem, "path", dte->dte_path);
    cJSON_AddStringToObject(elem, "level", log_level_to_string(ec->ev_level));
    cJSON_AddNumberToObject(elem, "odometer", odometer);
    snprintf_timestamp(value, sizeof(value), &ec->ev_odometer_timestamp);
    cJSON_AddStringToObject(elem, "odometer_timestamp", value);

    cJSON_AddItemToArray(root, elem);

    return 1;
}

struct dt_element_ops event_counter_ops = {
    .dto_emit = ev_emit_handler,
    .dto_match_selector = ev_match_select_handler,
};

bool
ev_root_match_select_handler(struct dt_element *dte, char *field, char *value)
{
    return true;
}

static size_t
ev_root_emit_handler(struct dt_element *dte, cJSON *root)
{
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
        .dte_is_root = true,
        .dte_file = REL_FILE(__FILE__),
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
