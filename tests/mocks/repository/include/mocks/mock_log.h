/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_MOCK_LOG_H
#define HSE_PLATFORM_MOCK_LOG_H

#define MAX_MSG_SIZE 500
#define MAX_NV_PAIRS 50
#define MAX_NV_SIZE 100

enum type_spec {
    ts_char = 1,
    ts_uchar = 2,
    ts_short = 3,
    ts_ushort = 4,
    ts_int = 5,
    ts_uint = 6,
    ts_long = 7,
    ts_ulong = 8,
    ts_float = 9,
    ts_double = 10,
    ts_ptr = 11
};

typedef struct logging_result {
    char msg_buffer[MAX_MSG_SIZE];
    char count;
    char names[MAX_NV_PAIRS][MAX_NV_SIZE];
    char values[MAX_NV_PAIRS][MAX_NV_SIZE];
    char index;
} logging_result;

extern logging_result shared_result;

void
test_preprocess_fmt_string(
    struct hse_log_fmt_state *state,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    ...);

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
    ...);

#endif /* HSE_PLATFORM_MOCK_LOG_H */
