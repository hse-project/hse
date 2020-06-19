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

/*
 * Prevent the -COMPILER- from merging or refetching accesses.  The
 * compiler is also forbidden from reordering successive instances
 * of ACCESS_ONCE(), but only when the compiler is aware of some
 * particular ordering.  One way to make the compiler aware of
 * ordering is to put the two invocations of ACCESS_ONCE() in
 * different C statements.
 *
 * CPU vs Compiler: This macro does absolutely -NOTHING- to prevent
 * the -CPU- from reordering, merging, or refetching absolutely
 * anything at any time.  Its main intended use is to mediate
 * communication between process-level code and irq/NMI handlers,
 * all running on the same CPU.
 */
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))

/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() asm volatile("" : : : "memory")

#define __printf(a, b) __attribute__((format(printf, a, b)))

#define __packed __attribute__((packed))

#ifndef __aligned
#define __aligned(SIZE) __attribute__((aligned(SIZE)))
#endif

#define __maybe_unused __attribute__((__unused__))

#define __read_mostly __attribute__((__section__(".read_mostly")))

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

#if GCC_VERSION < 40500
#define __builtin_ia32_pause() asm volatile("pause" : : : "memory")
#endif

#endif /* HSE_PLATFORM_COMPILER_H */
