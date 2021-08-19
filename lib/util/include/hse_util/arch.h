/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ARCH_H
#define HSE_PLATFORM_ARCH_H

#include <hse_util/timing.h>

#include <immintrin.h>

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES (64)
#endif

/* Max readahead pages offered by mcache.
 */
#define HSE_RA_PAGES_MAX ((128 * 1024) / PAGE_SIZE)

/* GCOV_EXCL_START */

#if __amd64__

#include <x86intrin.h>

#define VGETCPU_CPU_MASK    (0xfff)

static HSE_ALWAYS_INLINE uint64_t
get_cycles(void)
{
    return __rdtsc();
}

static HSE_ALWAYS_INLINE uint
raw_smp_processor_id(void)
{
    uint aux;

    __rdtscp(&aux);

    return aux & VGETCPU_CPU_MASK;
}

#else

static HSE_ALWAYS_INLINE uint64_t
get_cycles(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static HSE_ALWAYS_INLINE uint
raw_smp_processor_id(void)
{
    return sched_getcpu();
}

#endif

static HSE_ALWAYS_INLINE void
cpu_relax(void)
{
    _mm_pause();
}

size_t memlcp(const void *s1, const void *s2, size_t len);
size_t memlcpq(const void *s1, const void *s2, size_t len);

/* GCOV_EXCL_STOP */

#endif
