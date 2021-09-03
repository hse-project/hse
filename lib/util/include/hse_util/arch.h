/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ARCH_H
#define HSE_PLATFORM_ARCH_H

#include <hse_util/inttypes.h>

/* clang-format off */

/* Max readahead pages offered by mcache.
 */
#define HSE_RA_PAGES_MAX        ((128 * 1024) / PAGE_SIZE)

/* [HSE_REVISIT] Determine the dcache line size during compilation:
 *
 * e.g., -DLEVEL1_DCACHE_LINESIZE=$(getconf LEVEL1_DCACHE_LINESIZE)
 */
#define SMP_CACHE_BYTES         (64u)

/* GCOV_EXCL_START */

#if __amd64__

#include <hse_util/compiler.h>
#include <immintrin.h>
#include <x86intrin.h>

/* The Linux kernel stuffs the vCPU ID into the lower twelve
 * bits of the TSC AUX register, and the NUMA node ID into the
 * next higher eight bits.  This can be retrieved via the lsl,
 * rdtscp, and rdpid instructions.
 */
#define HSE_TSCAUX2VCPU(_aux)   ((_aux) & 0xfffu)
#define HSE_TSCAUX2NODE(_aux)   (((_aux) >> 12) & 0xffu)

static HSE_ALWAYS_INLINE uint64_t
get_cycles(void)
{
    return __rdtsc();
}

/**
 * hse_getcpu() - get calling thread's current vcpu and node IDs
 * @node:  returns calling thread's physical node ID
 *
 * Note that if you build with -DHSE_USE_RDPID then libhse will
 * run only on CPUs that support the rdpid instruction (similar
 * to compiling with -march=native).
 *
 * Note also that the optimizer should eliminate the node ptr
 * comparison and branch in most use cases (regardless of
 * whether node ptr is nil).
 */
static HSE_ALWAYS_INLINE uint
hse_getcpu(uint *node)
{
    uint aux;

#if HSE_USE_RDPID && __RDPID__
    aux = _rdpid_u32();
#else
    __rdtscp(&aux);
#endif

    if (node)
        *node = HSE_TSCAUX2NODE(aux);

    return HSE_TSCAUX2VCPU(aux);
}

static HSE_ALWAYS_INLINE void
cpu_relax(void)
{
    _mm_pause();
}

#else

#include <hse_util/timing.h>
#include <syscall.h>

static HSE_ALWAYS_INLINE uint64_t
get_cycles(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static HSE_ALWAYS_INLINE uint
hse_getcpu(uint *node)
{
    uint cpu;

    /* [HSE_REVISIT] Need to handle architectures that do not
     * support getcpu (see man vdso).
     */
    syscall(__NR_getcpu, &cpu, node, NULL);

    return cpu;
}

static HSE_ALWAYS_INLINE void
cpu_relax(void)
{
    /* [HSE_REVISIT] Burn a few cycles to avoid thrashing the memory bus...
     */
    while (hse_getcpu(NULL) >= UINT_MAX)
        continue;
}

#endif


size_t memlcp(const void *s1, const void *s2, size_t len);
size_t memlcpq(const void *s1, const void *s2, size_t len);

/* GCOV_EXCL_STOP */

#endif

/* clang-format on */
