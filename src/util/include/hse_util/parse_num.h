/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PARSE_NUM_H
#define HSE_PLATFORM_PARSE_NUM_H

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>

merr_t
parse_u64_range(const char *str, char **endptr, u64 min_accept, u64 max_accept, u64 *result);

merr_t
parse_s64_range(const char *str, char **endptr, s64 min_accept, s64 max_accept, s64 *result);

merr_t
parse_size_range(const char *str, u64 min_accept, u64 max_accept, u64 *result);

static inline merr_t
parse_size(const char *str, u64 *result)
{
    return parse_size_range(str, 0, 0, result);
}

#define __parse_signed_func(FNAME, TYP, TMIN, TMAX)               \
    static inline merr_t FNAME(const char *str, TYP *result)      \
    {                                                             \
        merr_t err;                                               \
        s64    tmp;                                               \
        err = parse_s64_range(str, (char **)0, TMIN, TMAX, &tmp); \
        if (!err)                                                 \
            *result = (TYP)tmp;                                   \
        return err;                                               \
    }

#define __parse_unsigned_func(FNAME, TYP, TMIN, TMAX)             \
    static inline merr_t FNAME(const char *str, TYP *result)      \
    {                                                             \
        merr_t err;                                               \
        u64    tmp;                                               \
        err = parse_u64_range(str, (char **)0, TMIN, TMAX, &tmp); \
        if (!err)                                                 \
            *result = (TYP)tmp;                                   \
        return err;                                               \
    }

/* Declarations (for readability) */
static inline merr_t
parse_u8(const char *str, u8 *result);
static inline merr_t
parse_s8(const char *str, s8 *result);

static inline merr_t
parse_u16(const char *str, u16 *result);
static inline merr_t
parse_s16(const char *str, s16 *result);

static inline merr_t
parse_u32(const char *str, u32 *result);
static inline merr_t
parse_s32(const char *str, s32 *result);

static inline merr_t
parse_u64(const char *str, u64 *result);
static inline merr_t
parse_s64(const char *str, s64 *result);

static inline merr_t
parse_uint(const char *str, unsigned int *result);
static inline merr_t
parse_int(const char *str, int *result);

static inline merr_t
parse_ulong(const char *str, unsigned long *result);
static inline merr_t
parse_long(const char *str, long *result);

/* definitions */
__parse_unsigned_func(parse_u8, u8, (u8)0, U8_MAX) __parse_signed_func(parse_s8, s8, S8_MIN, S8_MAX)

    __parse_unsigned_func(parse_u16, u16, (u16)0, U16_MAX)
        __parse_signed_func(parse_s16, s16, S16_MIN, S16_MAX)

            __parse_unsigned_func(parse_u32, u32, (u32)0, U32_MAX)
                __parse_signed_func(parse_s32, s32, S32_MIN, S32_MAX)

                    __parse_unsigned_func(parse_u64, u64, (u64)0, U64_MAX) __parse_signed_func(
                        parse_s64,
                        s64,
                        S64_MIN,
                        S64_MAX)

                        __parse_unsigned_func(parse_uint, unsigned int, (unsigned int)0, UINT_MAX)
                            __parse_signed_func(parse_int, int, INT_MIN, INT_MAX)

                                __parse_unsigned_func(
                                    parse_ulong,
                                    unsigned long,
                                    (unsigned long)0,
                                    ULONG_MAX)
                                    __parse_signed_func(parse_long, long, LONG_MIN, LONG_MAX)

#endif
