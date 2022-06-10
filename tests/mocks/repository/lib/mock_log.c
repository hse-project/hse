/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "util/src/logging_impl.h"

#include <mocks/mock_log.h>

thread_local logging_result shared_result;

/*
 * In order to allow testing the very lowest levels of the logging code, we
 * need to provide mock interfaces that will catch the calls to slog_internal_emit().
 *
 * For expediency we use a global structure to communicate between the mock
 * functions and the test code.  This is thread-safe, but different threads
 * will see only their own log message.
 */

void
test_preprocess_fmt_string(
    struct hse_log_fmt_state *state,
    const char               *func,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    ...)
{
    va_list args;

    va_start(args, hse_args);

    vpreprocess_fmt_string(state, func, fmt, new_fmt, new_len, hse_args, args);

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

    vpreprocess_fmt_string(state, __func__, fmt, new_fmt, new_len, hse_args, args);

    va_end(args);

    va_start(args, hse_args);

    finalize_log_structure(1, async, source_file, source_line, state, new_fmt, args);

    va_end(args);
}
