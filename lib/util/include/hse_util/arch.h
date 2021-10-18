/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ARCH_H
#define HSE_PLATFORM_ARCH_H

#include <hse_util/inttypes.h>
#include <hse_util/compiler.h>

/* clang-format off */

/* Max readahead pages offered by mcache.
 */
#define HSE_RA_PAGES_MAX        ((128 * 1024) / PAGE_SIZE)

#if (LEVEL1_DCACHE_LINESIZE > 64)
#define SMP_CACHE_BYTES         (LEVEL1_DCACHE_LINESIZE)
#else
#define SMP_CACHE_BYTES         (64u)
#endif

/* GCOV_EXCL_START */

#if __amd64__

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
 * Note that the optimizer should eliminate the node ptr
 * comparison and branch in most use cases (regardless of
 * whether node ptr is nil).
 */
static HSE_ALWAYS_INLINE uint
hse_getcpu(uint *node)
{
    uint aux;

#if __RDPID__
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

#if __s390x__
struct hse_s390x_todclk {
    __uint128_t zbits :  8; /* zero bits or tod carry */
    __uint128_t tod   : 64; /* high bits of 104-bit tod clock */
    __uint128_t todlo : 40; /* low bits of 104-bit tod clock */
    __uint128_t pbits : 16; /* programmable bits */
} HSE_PACKED;

static HSE_ALWAYS_INLINE uint64_t
get_cycles(void)
{
    struct hse_s390x_todclk todclk, *ptr = &todclk;

    __asm__ __volatile__ ("stcke %0" : "=Q" (*ptr) : : "cc");

    /* Bit 51 of ptr->tod ticks every 1us, so presumably bit 63
     * ticks every 1000/4096 nanoseconds (resolution higher than
     * 1us appears to depend on machine model).
     */
    return ptr->tod;
}

#else

#include <hse_util/timing.h>

#define get_cycles()    get_time_ns()
#endif

uint
hse_getcpu(uint *node);

static HSE_ALWAYS_INLINE void
cpu_relax(void)
{
    barrier();
}

#endif


size_t memlcp(const void *s1, const void *s2, size_t len);
size_t memlcpq(const void *s1, const void *s2, size_t len);

/* GCOV_EXCL_STOP */

#endif

/* clang-format on */
