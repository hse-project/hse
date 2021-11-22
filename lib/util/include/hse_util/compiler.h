/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_COMPILER_H
#define HSE_PLATFORM_COMPILER_H

#include "build_config.h"

/* clang-format off */

/* Ubuntu 18.04 uses glibc 2.27, and threads.h only exists in glibc >= 2.28 */
#if defined(__has_include) && !__has_include(<threads.h>)
#define thread_local            _Thread_local
#else
#include <threads.h>
#endif

/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier()               __asm__ __volatile__("" : : : "memory")

#define HSE_LIKELY(_expr)       __builtin_expect(!!(_expr), 1)
#define HSE_UNLIKELY(_expr)     __builtin_expect(!!(_expr), 0)

#ifdef SUPPORTS_ATTR_ALWAYS_INLINE
#define HSE_ALWAYS_INLINE       inline __attribute__((__always_inline__))
#else
#define HSE_ALWAYS_INLINE       inline
#endif

#ifdef SUPPORTS_ATTR_FORMAT
#define HSE_PRINTF(_fmtidx, _argidx) \
    __attribute__((__format__(__printf__, _fmtidx, _argidx)))
#else
#define HSE_PRINTF(_fmtidx, _argidx)
#endif

#ifdef SUPPORTS_ATTR_PACKED
#define HSE_PACKED              __attribute__((__packed__))
#else
#define HSE_PACKED
#endif

#ifdef SUPPORTS_ATTR_ALIGNED
#define HSE_ALIGNED(_size)      __attribute__((__aligned__(_size)))
#else
#define HSE_ALIGNED(_size)
#endif

#ifdef SUPPORTS_ATTR_SECTION
#define HSE_READ_MOSTLY         __attribute__((__section__(".read_mostly")))
#else
#define HSE_READ_MOSTLY
#endif

#ifdef SUPPORTS_ATTR_UNUSED
#define HSE_MAYBE_UNUSED        __attribute__((__unused__))
#else
#define HSE_MAYBE_UNUSED
#endif

#ifdef SUPPORTS_ATTR_USED
#define HSE_USED                __attribute__((__used__))
#else
#define HSE_USED
#endif

#ifdef SUPPORTS_ATTR_HOT
#define HSE_HOT                 __attribute__((__hot__))
#else
#define HSE_HOT
#endif

#ifdef SUPPORTS_ATTR_COLD
#define HSE_COLD                __attribute__((__cold__))
#else
#define HSE_COLD
#endif

#ifdef SUPPORTS_ATTR_RETURNS_NONNULL
#define HSE_RETURNS_NONNULL     __attribute__((__returns_nonnull__))
#else
#define HSE_RETURNS_NONNULL
#endif

#ifdef SUPPORTS_ATTR_CONST
#define HSE_CONST               __attribute__((__const__))
#else
#define HSE_CONST
#endif

#ifdef SUPPORTS_ATTR_WEAK
#define HSE_WEAK                __attribute__((__weak__))
#else
#define HSE_WEAK
#endif

#ifdef SUPPORTS_ATTR_SENTINEL
#define HSE_SENTINEL            __attribute__((__sentinel__))
#else
#define HSE_SENTINEL
#endif

#ifdef SUPPORTS_ATTR_NONNULL
/* HSE_NONNULL(...) cannot go at the end of the function definition */
#define HSE_NONNULL(...)        __attribute__((__nonnull__(__VA_ARGS__)))
#else
#define HSE_NONNULL(...)
#endif

#if HSE_MOCKING
#define MTF_STATIC              HSE_WEAK
#else
#define MTF_STATIC              static
#endif

/* clang-format on */

#endif /* HSE_PLATFORM_COMPILER_H */
