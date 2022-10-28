/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/logging/logging.h>
#include <hse/util/assert.h>
#include <hse/util/platform.h>
#include <hse/util/time.h>
#include <hse/util/data_tree.h>
#include <hse/util/event_counter.h>

static void
ev_get_timestamp(atomic_ulong *timestamp)
{
    struct timeval tv;

    gettimeofday(&tv, NULL);

    atomic_set(timestamp, (tv.tv_sec * USEC_PER_SEC) + tv.tv_usec);
}

static size_t
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

/**
 * emit_handler output fits into a JSON document.
 */
static merr_t
ev_emit_handler(struct dt_element *const dte, cJSON *const root)
{
    cJSON *elem;
    char buf[128];
    bool bad = false;
    struct event_counter *ec = dte->dte_data;
    const unsigned long odometer = atomic_read(&ec->ev_odometer);

    INVARIANT(dte);
    INVARIANT(cJSON_IsArray(root));

    elem = cJSON_CreateObject();
    if (ev(!elem))
        return merr(ENOMEM);

    snprintf_timestamp(buf, sizeof(buf), &ec->ev_odometer_timestamp);

    bad |= !cJSON_AddStringToObject(elem, "path", dte->dte_path);
    bad |= !cJSON_AddStringToObject(elem, "level", log_level_to_string(ec->ev_level));
    bad |= !cJSON_AddNumberToObject(elem, "odometer", odometer);
    bad |= !cJSON_AddStringToObject(elem, "odometer_timestamp", buf);

    if (ev(bad || !cJSON_AddItemToArray(root, elem)))
        cJSON_Delete(elem);

    return bad ? merr(ENOMEM) : 0;
}

struct dt_element_ops event_counter_ops = {
    .dto_emit = ev_emit_handler,
};

static struct dt_element_ops event_counter_root_ops = { 0 };

/* Install the root node for event counters. This is important because we need
 * to identify it as a ROOT node to get the right emit() behavior.
 */
void
event_counter_init(void)
{
    static struct dt_element hse_dte_event = {
        .dte_ops = &event_counter_root_ops,
        .dte_file = REL_FILE(__FILE__),
        .dte_line = __LINE__,
        .dte_func = __func__,
        .dte_path = EV_DT_PATH,
    };

    dt_add(&hse_dte_event);
}

void
event_counter(struct event_counter *ec)
{
    if (HSE_UNLIKELY(1 == atomic_inc_return(&ec->ev_odometer))) {
        struct dt_element *dte = &ec->ev_dte;

        snprintf(dte->dte_path, sizeof(dte->dte_path), "%s/%s/%s/%d",
                 EV_DT_PATH, basename(dte->dte_file), dte->dte_func, dte->dte_line);

        dt_add(dte);
    }

    if (!(ec->ev_flags & EV_FLAGS_NOTIME))
        ev_get_timestamp(&ec->ev_odometer_timestamp);
}
