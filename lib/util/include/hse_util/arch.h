/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_ARCH_H
#define HSE_PLATFORM_ARCH_H

#include <hse_util/page.h>
#include <hse_util/timing.h>

#include <sched.h>

/* MTF_MOCK_DECL(arch) */

#ifndef SMP_CACHE_BYTES
#define SMP_CACHE_BYTES (64)
#endif

/* Max readahead pages offered by mcache.
 */
#define HSE_RA_PAGES_MAX ((128 * 1024) / PAGE_SIZE)

/**
 * hse_meminfo() - Get current system-wide memory usage
 * @freep:    ptr to return bytes of free memory
 * @availp:   ptr to return bytes of available memory
 * @shift:    shift results by %shift bits
 *
 * %hse_meminfo() returns current free and available memory
 * sizes obtained from /proc/meminfo in userland and si_meminfo()
 * in the kernel.  The resulting sizes are in bytes, but the
 * caller can supply a non-zero %shift argment to obtain results
 * in different units (e.g., for MiB shift=20, for GiB shift=30).
 *
 * %freep and/or %availp may be NULL.
 */
/* MTF_MOCK */
void
hse_meminfo(unsigned long *freep, unsigned long *availp, unsigned int shift);


struct hse_cputopo {
    uint32_t core : 20;
    uint32_t node : 12;
};

#define hse_cpu2core(_cpuid)    (hse_cputopov[(_cpuid)].core)
#define hse_cpu2node(_cpuid)    (hse_cputopov[(_cpuid)].node)

extern struct hse_cputopo *hse_cputopov;

/**
 * hse_getcpu() - get calling thread's current cpu, node, and core ID
 * @cpu:   returns calling thread's virtual cpu ID
 * @core:  returns calling thread's physical core ID
 * @node:  returns calling thread's physical node ID
 *
 * Similar in function to Linux's getcpu() system call, but also returns
 * the core ID.
 */
static HSE_ALWAYS_INLINE void
hse_getcpu(uint *cpu, uint *node, uint *core)
{
    uint cpuid = raw_smp_processor_id();

    *cpu = cpuid;
    *node = hse_cpu2node(cpuid);
    *core = hse_cpu2core(cpuid);
}


#if HSE_MOCKING
#include "arch_ut.h"
#endif /* HSE_MOCKING */

#endif
