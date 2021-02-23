/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BARRIER_H
#define HSE_PLATFORM_BARRIER_H

/*
 * Compatible with linux when built with x86_64 SMP
 */

#include <hse_util/compiler.h>

/* HSE is not considered useful on non-smp systems; do not define
 * those memory barriers, to help catch errors
#define mb()                     barrier()
#define rmb()                    mb()
#define wmb()                    mb()
 */

/* Faster than mfence:  https://lore.kernel.org/patchwork/patch/850075/
 */
#if __amd64__
#define smp_mb() asm volatile("lock; addl $0,-4(%%rsp)" : : : "memory", "cc")

#else
#error smp_mb not implemented for this architecture
#endif

#define smp_rmb() smp_mb() /* HSE_REVISIT: lfence? */
#define smp_wmb() barrier()
#define smp_read_barrier_depends() \
    do {                           \
    } while (0)

#endif
