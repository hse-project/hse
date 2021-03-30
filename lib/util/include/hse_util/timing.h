/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TIMING_H
#define HSE_PLATFORM_TIMING_H

#include "_config.h"

#include <hse_util/base.h>
#include <hse_util/inttypes.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>

#include <time.h>
#include <unistd.h>

/* GCOV_EXCL_START */

static HSE_ALWAYS_INLINE u64
get_time_ns(void)
{
    struct timespec ts = { 0, 0 };

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static HSE_ALWAYS_INLINE int
get_realtime(struct timespec *ts)
{
    return clock_gettime(CLOCK_REALTIME, ts);
}


#if __amd64__
static HSE_ALWAYS_INLINE u64
get_cycles(void)
{
    return __builtin_ia32_rdtsc();
}

#else

#warning "using default implementation for get_cycles()"

/* If you change this you must update tsc_freq, tsc_mult,
 * and tsc_shift in timer.c to match.
 */
static HSE_ALWAYS_INLINE u64
get_cycles(void)
{
    return get_time_ns();
}
#endif


#if __amd64__
#define VGETCPU_CPU_MASK 0xfff
#define GDT_ENTRY_PER_CPU 15
#define __PER_CPU_SEG (GDT_ENTRY_PER_CPU * 8 + 3)

/* valgrind doesn't grok lsl, so use rdtscp if valgrind is enabled.
 *
 * [HSE_REVISIT] Use RDPID if available (see __getcpu()).
 */
static HSE_ALWAYS_INLINE unsigned int
raw_smp_processor_id(void)
{
    uint64_t aux;

#ifndef WITH_VALGRIND
    asm volatile("lsl %1,%0" : "=r"(aux) : "r"(__PER_CPU_SEG));
#else
    uint64_t rax, rdx;

    asm volatile("rdtscp" : "=a"(rax), "=d"(rdx), "=c"(aux) : :);
#endif

    return aux & VGETCPU_CPU_MASK;
}

#else
#error raw_smp_processor_id() not implemented for this architecture
#endif

#define smp_processor_id() raw_smp_processor_id()


static inline unsigned int
num_online_cpus(void)
{
    long nprocs;

    nprocs = sysconf(_SC_NPROCESSORS_ONLN);

    assert(nprocs > 0);

    return nprocs < 1 ? 1 : nprocs;
}

static inline unsigned int
num_conf_cpus(void)
{
    long nprocs;

    nprocs = sysconf(_SC_NPROCESSORS_CONF);

    assert(nprocs > 0);

    return nprocs < 1 ? 1 : nprocs;
}

/* GCOV_EXCL_STOP */

#endif
