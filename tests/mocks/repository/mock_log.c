/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "../src/logging_impl.h"

#include "mock_log.h"

logging_result shared_result;

/*
 * In order to allow testing the very lowest levels of the logging code, we
 * need to provide mock interfaces that will catch the calls to the
 * system-level routines printk_emit() and syslog().
 *
 * For expediency we use a global structure to communicate between the mock
 * functions and the test code. This is not thread-safe and would have to
 * be changed if the tests had to run multi-threaded.
 */

#if defined(__HSE_KERNEL_UT__)

/*
 * Side-effect of slab.h
 */
#ifdef printk
#undef printk
#endif

int
printk(const char *fmt, ...)
{
    int     rc;
    va_list args;

    va_start(args, fmt);
    rc = vprintf(fmt, args);
    va_end(args);

    return rc;
}

int
printk_emit(int facility, int level, const char *dict, size_t dictlen, const char *fmt, ...)
{
    int     rc;
    va_list args;

    va_start(args, fmt);
    rc = vprintk_emit(facility, level, dict, dictlen, fmt, args);
    va_end(args);

    return rc;
}

int
vprintk_emit(
    int         facility,
    int         level,
    const char *dict,
    size_t      dictlen,
    const char *fmt,
    va_list     args)
{
    int rc;

    rc = vsnprintf(shared_result.msg_buffer, MAX_MSG_SIZE, fmt, args);

    const char *p = dict;
    int         index = 0;

    while (p < (dict + dictlen) && index < MAX_NV_PAIRS) {
        char *q = shared_result.names[index];

        while (p < (dict + dictlen) && *p != '=')
            *q++ = *p++;
        *q = 0;

        if (*p != '=')
            break;

        ++p;
        q = shared_result.values[index];

        while (p < (dict + dictlen) && *p != 0)
            *q++ = *p++;
        *q = 0;

        ++p;
        ++index;
    }

    shared_result.count = index;

    return rc;
}

#else  /* defined(__HSE_KERNEL_UT__) */

void
vsyslog(int priority, const char *fmt, va_list args)
{
    vsnprintf(shared_result.msg_buffer, MAX_MSG_SIZE, fmt, args);
}
#endif /* defined(__HSE_KERNEL_UT__) */

void
test_preprocess_fmt_string(
    struct hse_log_fmt_state *state,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    ...)
{
    va_list args;

    va_start(args, hse_args);

    vpreprocess_fmt_string(state, fmt, new_fmt, new_len, hse_args, args);

    va_end(args);
}

void
test_finalize_log_structure(
    struct hse_log_fmt_state *state,
    bool                      async,
    char *                    source_file,
    s32                       source_line,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    ...)
{
    va_list args;

    va_start(args, hse_args);

    vpreprocess_fmt_string(state, fmt, new_fmt, new_len, hse_args, args);

    va_end(args);

    va_start(args, hse_args);

    finalize_log_structure(1, async, source_file, source_line, state, new_fmt, args);

    va_end(args);
}
