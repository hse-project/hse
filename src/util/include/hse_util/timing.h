/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TIMING_H
#define HSE_PLATFORM_TIMING_H

#include <hse_util/base.h>
#include <hse_util/inttypes.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>

#include <time.h>
#include <unistd.h>

BullseyeCoverageSaveOff

static __always_inline u64
get_time_ns(void)
{
    struct timespec ts = { 0, 0 };

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (u64)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static __always_inline int
get_realtime(struct timespec *ts)
{
    return clock_gettime(CLOCK_REALTIME, ts);
}


#if __amd64__
static __always_inline u64
get_cycles(void)
{
    unsigned int tickl, tickh;

    __asm__ __volatile__("rdtsc" : "=a"(tickl), "=d"(tickh));
    return ((unsigned long long)tickh << 32) | tickl;
}

#else
#error get_cyles() not implemented for this architecture
#endif


#if __amd64__
#define VGETCPU_CPU_MASK 0xfff
#define GDT_ENTRY_PER_CPU 15
#define __PER_CPU_SEG (GDT_ENTRY_PER_CPU * 8 + 3)

/* valgrind doesn't grok lsl, so use rdtscp if valgrind is enabled.
 *
 * [HSE_REVISIT] Use RDPID if available (see __getcpu()).
 */
static __always_inline unsigned int
raw_smp_processor_id(void)
{
    uint64_t aux;

#ifdef NVALGRIND
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

BullseyeCoverageRestore

#endif
