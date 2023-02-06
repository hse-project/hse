/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_ARCH_H
#define HSE_PLATFORM_ARCH_H

#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

#include <hse/util/compiler.h>
#include <hse/util/time.h>

/* clang-format off */

#if (LEVEL1_DCACHE_LINESIZE > 64)
#define HSE_L1D_LINESIZE        (LEVEL1_DCACHE_LINESIZE)
#else
#define HSE_L1D_LINESIZE        (64)
#endif

/* GCOV_EXCL_START */

#if __amd64__

#include <immintrin.h>
#include <x86intrin.h>

/* Adjacent Cacheline Prefetch is enabled by default on most amd64
 * systems that support it.
 */
#define HSE_ACP_LINESIZE        (HSE_L1D_LINESIZE * 2)
#define HSE_L1X_LINESIZE        (HSE_L1D_LINESIZE)

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

/* [HSE_REVISIT] Are there any other architectures that support
 * Adjacent Cacheline Prefetch?  Assume no for now...
 */
#define HSE_ACP_LINESIZE        (HSE_L1D_LINESIZE)

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

static HSE_ALWAYS_INLINE uint64_t
get_time_ns(void)
{
    __uint128_t cycles = get_cycles() >> 2;

    /* Convert from fractions of (usecs / 1024) to nsecs.
     */
    return (uint64_t)((cycles * 1000) / 1024);
}

#else

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

#if !__s390x__
static HSE_ALWAYS_INLINE uint64_t
get_time_ns(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (uint64_t)(ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec);
}
#endif

/* HSE_L1D_ALIGNED - Used to separate non-related fields in a structure
 * by one cacheline to avoid false sharing.
 *
 * HSE_ACP_ALIGNED - Used to separate non-related fields in a structure
 * by one or more cachelines to avoid false sharing due to Adjacent
 * Cacheline Prefetch (e.g., two cache lines on amd64, otherwise one).
 *
 * HSE_L1X_ALIGNED - Used to align to the next cacheline when Adjacent
 * Cacheline Prefetch is available, otherwise has no effect.  Use of
 * HSE_L1X_ALIGNED should always be paired with HSE_ACP_ALIGNED.
 */
#define HSE_L1D_ALIGNED         HSE_ALIGNED(HSE_L1D_LINESIZE)
#define HSE_ACP_ALIGNED         HSE_ALIGNED(HSE_ACP_LINESIZE)

#if (HSE_L1X_LINESIZE > 0)
#define HSE_L1X_ALIGNED         HSE_ALIGNED(HSE_L1X_LINESIZE)
#else
#define HSE_L1X_ALIGNED
#endif

/**
 * memlcp() - return longest common prefix
 * @s1:     byte array one
 * @s2:     byte array two
 * @len:    max length to compare
 *
 * Return: %memlcp compares byte array %s1 to byte array %s2,
 * returning the maximum length at which they compare identical.
 */
static HSE_ALWAYS_INLINE size_t
memlcp(const void *s1, const void *s2, const size_t len)
{
    const uint8_t *lhs = s1;
    const uint8_t *rhs = s2;
    size_t i = 0;

    while (i < (len & ~7ul)) {
        if (memcmp(lhs + i, rhs + i, 8) != 0)
            break;
        i += 8;
    }

    while (i < len) {
        if (lhs[i] != rhs[i])
            break;
        i++;
    }

    return i;
}

/**
 * memlcpq() - return longest common prefix within nearest quadword
 * @s1:     byte array one
 * @s2:     byte array two
 * @len:    max length to compare
 *
 * Return: %memlcpq compares byte array %s1 to byte array %s2,
 * returning the maximum length at which they compare identical,
 * rounded down to the nearest quadword.
 */
static HSE_ALWAYS_INLINE size_t
memlcpq(const void *s1, const void *s2, const size_t len)
{
    const uint8_t *lhs = s1;
    const uint8_t *rhs = s2;
    size_t i = 0;

    while (i < (len & ~7ul)) {
        if (memcmp(lhs + i, rhs + i, 8) != 0)
            break;
        i += 8;
    }

    return i;
}

/* GCOV_EXCL_STOP */

#endif

/* clang-format on */
