/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ERROR_COUNTER_H
#define HSE_PLATFORM_ERROR_COUNTER_H

#include <hse_util/arch.h>
#include <hse_util/compiler.h>
#include <hse_util/data_tree.h>
#include <hse_util/atomic.h>
#include <hse_util/time.h>

/* clang-format off */

#define EV_FLAGS_HSE_LOG    (0x01u)
#define EV_FLAGS_NOTIME     (0x02u)

struct event_counter {
    atomic_t           ev_odometer;
    int                ev_pri;
    atomic64_t         ev_odometer_timestamp;
    atomic64_t         ev_trip_odometer_timestamp;
    int                ev_trip_odometer;
    u32                ev_flags;
    u64                ev_priv;
    const char        *ev_file;
    int                ev_line;
    struct dt_element  ev_dte;
} HSE_ALIGNED(64);

extern struct dt_element_ops event_counter_ops;

#define ev_impl(_expr, _pri, _flags)                            \
    ({                                                          \
        typeof(_expr) _tmp = (_expr);                           \
                                                                \
        if (HSE_UNLIKELY(_tmp)) {                               \
            static struct event_counter hse_ev _dt_section = {  \
                .ev_odometer = 0,                               \
                .ev_pri = (_pri),                               \
                .ev_flags = (_flags),                           \
                .ev_file = __FILE__,                            \
                .ev_line = __LINE__,                            \
                .ev_dte = {                                     \
                    .dte_data = &hse_ev,                        \
                    .dte_ops = &event_counter_ops,              \
                    .dte_type = DT_TYPE_ERROR_COUNTER,          \
                    .dte_line = __LINE__,                       \
                    .dte_file = __FILE__,                       \
                    .dte_func = __func__,                       \
                },                                              \
            };                                                  \
                                                                \
            event_counter(&hse_ev);                             \
        }                                                       \
                                                                \
        _tmp;                                                   \
    })

#include <hse_util/logging.h>

/* Use ev_info() for run-of-the-mill events and low overhead event
 * counting of hot paths.  It's about 10x faster than the other
 * forms because it never udpates the time stamp.
 */
#define ev_debug(_expr)     ev_impl((_expr), HSE_LOGPRI_DEBUG, EV_FLAGS_NOTIME)
#define ev_info(_expr)      ev_impl((_expr), HSE_LOGPRI_INFO, EV_FLAGS_NOTIME)
#define ev_warn(_expr)      ev_impl((_expr), HSE_LOGPRI_WARN, 0)
#define ev_err(_expr)       ev_impl((_expr), HSE_LOGPRI_ERR, 0)
#define ev(_expr)           ev_impl((_expr), HSE_LOGPRI_ERR, 0)

/* clang-format on */

/* NON-API Functions */
void
ev_get_timestamp(atomic64_t *timestamp);

size_t
snprintf_timestamp(char *buf, size_t buf_sz, atomic64_t *timestamp);

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

/**
 * ev_match_select_handler - Support data_tree's match select option
 * @dte:    struct dt_element *
 * @field:  char *, name of a field in the event_counter structure
 * @value:  char *, stringified value for comparison
 *
 * Returns true if dte->ec->field == value, else false
 */
bool
ev_match_select_handler(struct dt_element *dte, char *field, char *value);

/**
 * ev_root_match_select_handler - Support data_tree's match select option
 * @dte:    struct dt_element *
 * @field:  char *, name of a field in the event_counter structure
 * @value:  char *, stringified value for comparison
 *
 * Always returns true. This may seem silly, but we always need the root
 * elements in the yaml output.
 */
bool
ev_root_match_select_handler(struct dt_element *dte, char *field, char *value);

#endif /* HSE_PLATFORM_ERROR_COUNTER_H */
