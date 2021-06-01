/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ERROR_COUNTER_H
#define HSE_PLATFORM_ERROR_COUNTER_H

#include <hse_util/arch.h>
#include <hse_util/compiler.h>
#include <hse_util/logging.h>
#include <hse_util/data_tree.h>
#include <hse_util/atomic.h>
#include <hse_util/time.h>

struct event_counter {
    atomic64_t         ev_odometer_timestamp;
    atomic64_t         ev_trip_odometer_timestamp;
    int                ev_trip_odometer;
    int                ev_log_level;
    atomic_t           ev_odometer;
    u32                ev_flags;
    struct dt_element *ev_dte;
} HSE_ALIGNED(SMP_CACHE_BYTES);

#define EV_FLAGS_HSE_LOG 0x1
#define EV_LIST_FLAG_SINCE_LAST_CHECKPOINT 0x1

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
event_counter_init(void);

/**
 * event_counter() - Core of the Event Counter functionality. Called by macro.
 * @dte:        struct dt_element *, pre-allocated dt_element that wraps the EV
 * @ec: struct event_counter *, pre-allocated event counter structure
 *
 * Called, under the covers by the ERROR_COUNTER macros, event_counter()
 * updates the main odometer and timestamp.
 */
void
event_counter(struct dt_element *dte, struct event_counter *ec);

/**
 * ev_pathname() - Returns the just the filename for a given path
 * @path: const char *, file path
 *
 * ev_pathname takes a path string, e.g. "/a/b/c" and returns a pointer
 * to just the filename, e.g. "c".
 *
 * Does NOT modify the passed-in path string.
 *
 * Return: char *
 */
const char *
ev_pathname(const char *path);

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

extern struct dt_element_ops event_counter_ops;

/**
 * ERROR_COUNTER macros: Immediately below this comment you will find
 * declarations and explanations of five macros that combine to support
 * the three developer-visible forms of the ERROR_COUNTER macro.
 *
 * When coding, the developer can use either of the following three forms:
 * 1. ERROR_COUNTER() - creates a struct event_counter and struct dt_element.
 *     Further invocations of the ERROR_COUNTER() on the same line of code
 *     will update the existing data structure.
 * 2. ERROR_COUNTER(name) - Also creates a second struct dt_element in the
 *     data_tree that is a link to the original. This allows for a more
 *     flexible namespace for event Counters.
 * 3. ERROR_COUNTER(priority, name) - Like the second macro, this one creates
 *     both an original event_counter and a link. It also sets a priority
 *     level that can be used to narrow a selection of event Counters to be
 *     operated on by the dt_iterate_* functions. The default priority of
 *     event Counters that are not created through this version of the
 *     macro is HSE_INFO_VAL
 *
 * The remaining two macros (EV_GET_MACRO and ERROR_COUNTER) are functions
 * used to distinguish between which version of the macro that the developer
 * intended to use (i.e. handling the variable number of arguments to
 * ERROR_COUNTER().
 */

/**
 * ERROR_COUNTER0() - Basic version of the macro with automatic name generation.
 *
 * The first invocation of this macro will insert the data tree element
 * (struct dt_element) into the tree with a odometer count of 1 and with the
 * odometer timestamp initialized to the current time (struct timeval).
 *
 * The use of static structures here allows for event Counters to be
 * created without a memory allocation (which may be problematic in the
 * situtations in which you are likely to use an event Counter.
 *
 * The path for the event Counter will be look like this:
 * "/data/event_counter/<component>/<filename>/<function>/<line_number>"
 * with component being a const char string set in the file, filename is
 * found using the pre-processor's __FILE__ (and then truncated to just
 * the filename and not the path), function, and line number are also
 * pulled from the pre-processor.
 */
#define ERROR_COUNTER0() ERROR_COUNTER3(HSE_INFO_VAL, -1)

/**
 * ERROR_COUNTER1(pri) - Version of the macro that supports an extra
 *     argument that is used to set .ev_priority to something besides HSE_INFO
 */
#define ERROR_COUNTER1(pri, foo) ERROR_COUNTER3(pri, -1)

/**
 * ERROR_COUNTER2(pri, rock) - Third form of the ERROR_COUNTER macro.
 *     In addition to the functionality of ERROR_COUNTER1() this version
 *     allows the developer to specify a debugging "rock", i.e. a 64-bit
 *     value that is opaque to the Event Counter mechanism.
 *
 * The rock will be stored in a small circular buffer with an identifier
 * for the Event Counter that it came from.
 *
 * <The rock supporting functionality is still to come.>
 */
#define ERROR_COUNTER2(pri, foo, rock) ERROR_COUNTER3(pri, rock)

#define ERROR_COUNTER3(pri, rock)                 \
    do {                                          \
        static struct event_counter ec = {        \
            .ev_odometer = ATOMIC_INIT(0),        \
            .ev_trip_odometer = 0,                \
            .ev_log_level = pri,                  \
            .ev_flags = 0,                        \
        };                                        \
        static struct dt_element dte = {          \
            .dte_data = &ec,                      \
            .dte_ops = &event_counter_ops,        \
            .dte_type = DT_TYPE_ERROR_COUNTER,    \
            .dte_flags = DT_FLAGS_NON_REMOVEABLE, \
            .dte_line = __LINE__,                 \
            .dte_file = __FILE__,                 \
            .dte_func = __func__,                 \
            .dte_comp = COMPNAME,                 \
        };                                        \
                                                  \
        event_counter(&dte, &ec);                 \
    } while (0)

/**
 * EV_GET_MACRO and ERROR_COUNTER - Front end to the ERROR_COUNTER macros
 *     allowing selection of the appropriate underlying macro depending on
 *     the number of arguments given to the ERROR_COUNTER() macro.
 *
 * The EV_GET_MACRO is used to determine which of the three ERROR_COUNTERX
 * macros to call (see above). The macro is passed all of the args given
 * to the ERROR_COUNTER macro (of which there could be zero, one, or two.
 * If two arguments were given then _0, _1, and _2 will have values and
 * therefore NAME will be the next argument (ERROR_COUNTER2). If one
 * argument was given then only _0, and _1 will have values, and ERROR_COUNTER2
 * will be absorbed as the third argument making ERROR_COUNTER1 the NAME
 * to be returned. The ## at the beginning of __VA_ARGS__ makes sure that
 * no arguments being passed is still seen as a single argument. So,
 * with no arguments given, _0 is taken, ERROR_COUNTER2 becomes _1,
 * ERROR_COUNTER1 becomes _2, and that makes NAME ERROR_COUNTER1.
 *
 * NAME is then married to (__VA_ARGS__) to make the correct form,
 * e.g.: ERROR_COUNTER2(pri, name)
 */

#define ERROR_COUNTER(...) \
    EV_GET_MACRO(_0, ##__VA_ARGS__, ERROR_COUNTER2, ERROR_COUNTER1, ERROR_COUNTER0)(__VA_ARGS__)

/**
 * ev(e) can replace most of the variations uses before:
 *      ec(e) -> ev(e)
 *      merr_ec(e) -> merr(ev(e))
 *      ec_count(e) -> ev(e)
 */

#define EV_GET_MACRO(_1, _2, _3, NAME, ...) NAME

#define EV_PRI(e, pri, mark)       \
    ({                             \
        ERROR_COUNTER3((pri), -1); \
        (e);                       \
    })

#ifdef WITH_COVERAGE
#define EV1(e) EV_PRI(e, HSE_ERR_VAL, HSE_MARK)
#define EV2(e, pri, mark) EV_PRI(e, pri, mark)
#else
#define EV1(e)                                                        \
    ({                                                                \
        typeof(e) _tmp = e;                                           \
        HSE_UNLIKELY(_tmp) ? EV_PRI(_tmp, HSE_INFO_VAL, HSE_MARK) : _tmp; \
    })
#define EV2(e, pri, mark)                                \
    ({                                                   \
        typeof(e) _tmp = e;                              \
        HSE_UNLIKELY(_tmp) ? EV_PRI(_tmp, pri, mark) : _tmp; \
    })
#endif

/* The preferred, concise, expression when a priority is specified is, e.g.:
 *          ev(rc, HSE_ERR)
 * This expression expands to:
 *          EV2(rc, HSE_ERR_VAL, HSE_MARK)
 * However it is also possible to write:
 *          ev(rc, HSE_ERR_VAL)
 * This expression expands to:
 *          EV_PRI_NO_MARK(rc, HSE_ERR_VAL)
 * And subsequently to:
 *          EV2(rc, HSE_ERR_VAL, HSE_MARK)
 */
#define EV_PRI_NO_MARK(e, pri) EV2(e, pri, HSE_MARK)
#define ev(...) EV_GET_MACRO(__VA_ARGS__, EV2, EV_PRI_NO_MARK, EV1)(__VA_ARGS__)

#endif /* HSE_PLATFORM_ERROR_COUNTER_H */
