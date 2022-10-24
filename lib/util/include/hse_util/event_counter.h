/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_EVENT_COUNTER_H
#define HSE_PLATFORM_EVENT_COUNTER_H

#include <stdint.h>
#include <syslog.h>

#include <hse_util/atomic.h>
#include <hse_util/compiler.h>
#include <hse_util/data_tree.h>

/* clang-format off */

#define EV_FLAGS_NOTIME (0x01u)

#define EV_DT_PATH      "/data/events"

struct event_counter {
    atomic_ulong       ev_odometer;
    uint32_t           ev_flags;
    int                ev_level;
    atomic_ulong       ev_odometer_timestamp;
    const char        *ev_file;
    int                ev_line;
    struct dt_element  ev_dte;
} HSE_ALIGNED(64);

extern struct dt_element_ops event_counter_ops;

#define ev_impl(_expr, _level, _flags)                          \
    ({                                                          \
        typeof(_expr) _tmp = (_expr);                           \
                                                                \
        if (HSE_UNLIKELY(_tmp)) {                               \
            static struct event_counter hse_ev _dt_section = {  \
                .ev_odometer = 0,                               \
                .ev_level = (_level),                           \
                .ev_flags = (_flags),                           \
                .ev_file = REL_FILE(__FILE__),                  \
                .ev_line = __LINE__,                            \
                .ev_dte = {                                     \
                    .dte_data = &hse_ev,                        \
                    .dte_ops = &event_counter_ops,              \
                    .dte_line = __LINE__,                       \
                    .dte_file = REL_FILE(__FILE__),             \
                    .dte_func = __func__,                       \
                },                                              \
            };                                                  \
                                                                \
            event_counter(&hse_ev);                             \
        }                                                       \
                                                                \
        _tmp;                                                   \
    })

/* Use ev_info() for run-of-the-mill events and low overhead event
 * counting of hot paths.  It's about 10x faster than the other
 * forms because it never udpates the time stamp.
 */
#define ev_debug(_expr)     ev_impl((_expr), LOG_DEBUG, EV_FLAGS_NOTIME)
#define ev_info(_expr)      ev_impl((_expr), LOG_INFO, EV_FLAGS_NOTIME)
#define ev_warn(_expr)      ev_impl((_expr), LOG_WARNING, 0)
#define ev_err(_expr)       ev_impl((_expr), LOG_ERR, 0)
#define ev(_expr)           ev_impl((_expr), LOG_ERR, 0)

/* clang-format on */

/* API Functions */
/**
 * event_counter_init() - create data_tree framework for Event Counters
 *
 * event_counter_init is called, under the covers, by the ERROR_COUNTER
 * macros. On the first invocation only it will guarantee that the main
 * debug data tree is initialized, and the event_counter root node is
 * created.
 *
 * Return: void.
 */
void
event_counter_init(void) HSE_COLD;

/**
 * event_counter() - Core of the Event Counter functionality. Called by macro.
 * @ec: struct event_counter *, pre-allocated event counter structure
 *
 * Updates the main odometer and timestamp.
 */
void
event_counter(struct event_counter *ec);

#endif /* HSE_PLATFORM_EVENT_COUNTER_H */
