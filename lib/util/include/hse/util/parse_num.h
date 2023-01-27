/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PARSE_NUM_H
#define HSE_PLATFORM_PARSE_NUM_H

#include <stdint.h>

#include <hse/error/merr.h>

#pragma GCC visibility push(default)

merr_t
parse_u64_range(
    const char *str,
    char **endptr,
    uint64_t min_accept,
    uint64_t max_accept,
    uint64_t *result);

merr_t
parse_s64_range(
    const char *str,
    char **endptr,
    int64_t min_accept,
    int64_t max_accept,
    int64_t *result);

merr_t
parse_size_range(const char *str, uint64_t min_accept, uint64_t max_accept, uint64_t *result);

static inline merr_t
parse_size(const char *str, uint64_t *result)
{
    return parse_size_range(str, 0, 0, result);
}

#define __parse_signed_func(FNAME, TYP, TMIN, TMAX)               \
    static inline merr_t FNAME(const char *str, TYP *result)      \
    {                                                             \
        merr_t err;                                               \
        int64_t tmp;                                              \
        err = parse_s64_range(str, (char **)0, TMIN, TMAX, &tmp); \
        if (!err)                                                 \
            *result = (TYP)tmp;                                   \
        return err;                                               \
    }

#define __parse_unsigned_func(FNAME, TYP, TMIN, TMAX)             \
    static inline merr_t FNAME(const char *str, TYP *result)      \
    {                                                             \
        merr_t err;                                               \
        uint64_t tmp;                                             \
        err = parse_u64_range(str, (char **)0, TMIN, TMAX, &tmp); \
        if (!err)                                                 \
            *result = (TYP)tmp;                                   \
        return err;                                               \
    }

/* Declarations (for readability) */
static inline merr_t
parse_u8(const char *str, uint8_t *result);
static inline merr_t
parse_s8(const char *str, int8_t *result);

static inline merr_t
parse_u16(const char *str, uint16_t *result);
static inline merr_t
parse_s16(const char *str, int16_t *result);

static inline merr_t
parse_u32(const char *str, uint32_t *result);
static inline merr_t
parse_s32(const char *str, int32_t *result);

static inline merr_t
parse_u64(const char *str, uint64_t *result);
static inline merr_t
parse_s64(const char *str, int64_t *result);

static inline merr_t
parse_uint(const char *str, unsigned int *result);
static inline merr_t
parse_int(const char *str, int *result);

static inline merr_t
parse_ulong(const char *str, unsigned long *result);
static inline merr_t
parse_long(const char *str, long *result);

#pragma GCC visibility pop

// clang-format off
/* Definitions - these are macros expanded into functions
 */
__parse_unsigned_func(parse_u8, uint8_t, (uint8_t)0, UINT8_MAX)
__parse_signed_func(parse_s8, int8_t, INT8_MIN, INT8_MAX)

__parse_unsigned_func(parse_u16, uint16_t, (uint16_t)0, UINT16_MAX)
__parse_signed_func(parse_s16, int16_t, INT16_MIN, INT16_MAX)

__parse_unsigned_func(parse_u32, uint32_t, (uint32_t)0, UINT32_MAX)
__parse_signed_func(parse_s32, int32_t, INT32_MIN, INT32_MAX)

__parse_unsigned_func(parse_u64, uint64_t, (uint64_t)0, UINT64_MAX)
__parse_signed_func(parse_s64, int64_t, INT64_MIN, INT64_MAX)

__parse_unsigned_func(parse_uint, unsigned int, (unsigned int)0, UINT_MAX)
__parse_signed_func(parse_int, int, INT_MIN, INT_MAX)

__parse_unsigned_func(parse_ulong, unsigned long, (unsigned long)0, ULONG_MAX)
__parse_signed_func(parse_long, long, LONG_MIN, LONG_MAX)
// clang-format on

#endif
