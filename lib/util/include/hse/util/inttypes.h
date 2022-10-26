/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_INTTYPES_H
#define HSE_PLATFORM_INTTYPES_H

#include <hse/util/base.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

#define U8_MAX UINT8_MAX
#define S8_MAX INT8_MAX
#define S8_MIN INT8_MIN

#define U16_MAX UINT16_MAX
#define S16_MAX INT16_MAX
#define S16_MIN INT16_MIN

#define U32_MAX UINT32_MAX
#define S32_MAX INT32_MAX
#define S32_MIN INT32_MIN

#define U64_MAX UINT64_MAX
#define S64_MAX INT64_MAX
#define S64_MIN INT64_MIN

#endif
