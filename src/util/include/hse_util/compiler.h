/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_COMPILER_H
#define HSE_PLATFORM_COMPILER_H

/*
 * Assumes gcc
 */

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() asm volatile("" : : : "memory")

#define __printf(a, b) __attribute__((format(printf, a, b)))

#define __packed __attribute__((packed))

#ifndef __aligned
#define __aligned(SIZE) __attribute__((aligned(SIZE)))
#endif

#define __read_mostly   __attribute__((__section__(".read_mostly")))
#define __maybe_unused  __attribute__((__unused__))
#define __used          __attribute__((__used__))
#define __hot           __attribute__((__hot__))
#define __cold          __attribute__((__cold__))

/*
 * There are multiple ways GCC_VERSION could be defined.  This mimics
 * the kernel's definition in include/linux/compiler-gcc.h.
 */
#define GCC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)

#if GCC_VERSION < 40700
#define _Static_assert(...)
#endif

#ifndef _BullseyeCoverage
#define _BullseyeCoverage 0
#endif

#if _BullseyeCoverage
#define BullseyeCoverageSaveOff _Pragma("BullseyeCoverage save off")
#define BullseyeCoverageRestore _Pragma("BullseyeCoverage restore")

#ifndef _Static_assert
#define _Static_assert(...)
#endif

#else
#define BullseyeCoverageSaveOff
#define BullseyeCoverageRestore
#endif

#if __amd64__
static __always_inline void
cpu_relax(void)
{
    asm volatile("rep; nop" ::: "memory");
}

#else
#error cpu_relax() not implemented for this architecture
#endif

#endif /* HSE_PLATFORM_COMPILER_H */
