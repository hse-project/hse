/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_COMPILER_H
#define HSE_PLATFORM_COMPILER_H

#include "build_config.h"

/* Ubuntu 18.04 uses glibc 2.27, and threads.h only exists in glibc >= 2.28 */
#if defined(__has_include) && !__has_include(<threads.h>)
#define thread_local _Thread_local
#else
#include <threads.h>
#endif

#if HSE_MOCKING
#define hse_static
#else
#define hse_static static
#endif

/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() asm volatile("" : : : "memory")

#define HSE_LIKELY(x)   __builtin_expect(!!(x), 1)
#define HSE_UNLIKELY(x) __builtin_expect(!!(x), 0)
#ifdef SUPPORTS_ATTR_ALWAYS_INLINE
#define HSE_ALWAYS_INLINE inline __attribute__((always_inline))
#else
#define HSE_ALWAYS_INLINE inline
#endif
#ifdef SUPPORTS_ATTR_FORMAT
#define HSE_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define HSE_PRINTF(a, b)
#endif
#ifdef SUPPORTS_ATTR_PACKED
#define HSE_PACKED __attribute__((packed))
#else
#define HSE_PACKED
#endif
#ifdef SUPPORTS_ATTR_ALIGNED
#define HSE_ALIGNED(SIZE) __attribute__((aligned(SIZE)))
#else
#define HSE_ALIGNED(SIZE)
#endif
#ifdef SUPPORTS_ATTR_SECTION
#define HSE_READ_MOSTLY __attribute__((section(".read_mostly")))
#else
#define HSE_READ_MOSTLY
#endif
#ifdef SUPPORTS_ATTR_UNUSED
#define HSE_MAYBE_UNUSED __attribute__((unused))
#else
#define HSE_MAYBE_UNUSED
#endif
#ifdef SUPPORTS_ATTR_USED
#define HSE_USED __attribute__((used))
#else
#define HSE_USED
#endif
#ifdef SUPPORTS_ATTR_HOT
#define HSE_HOT __attribute__((hot))
#else
#define HSE_HOT
#endif
#ifdef SUPPORTS_ATTR_COLD
#define HSE_COLD __attribute__((cold))
#else
#define HSE_COLD
#endif
#ifdef SUPPORTS_ATTR_RETURNS_NONNULL
#define HSE_RETURNS_NONNULL __attribute__((returns_nonnull))
#else
#define HSE_RETURNS_NONNULL
#endif
#ifdef SUPPORTS_ATTR_CONST
#define HSE_CONST __attribute__((const))
#else
#define HSE_CONST
#endif
#ifdef SUPPORTS_ATTR_WEAK
#define HSE_WEAK __attribute__((weak))
#else
#define HSE_WEAK
#endif
#ifdef SUPPORTS_ATTR_SENTINEL
#define HSE_SENTINEL __attribute__((sentinel))
#else
#define HSE_SENTINEL
#endif
#ifdef SUPPORTS_ATTR_NONNULL
/* HSE_NONNULL(...) cannot go at the end of the function declaration */
#define HSE_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define HSE_NONNULL(...)
#endif

#endif /* HSE_PLATFORM_COMPILER_H */
