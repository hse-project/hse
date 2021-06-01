/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PLATFORM_H
#define HSE_PLATFORM_PLATFORM_H

#include <hse_util/base.h>
#include <hse_util/arch.h>
#include <hse_util/hse_err.h>

/* MTF_MOCK_DECL(platform) */

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

extern merr_t hse_platform_init(void);
extern void hse_platform_fini(void);

#if HSE_MOCKING
#include "platform_ut.h"
#endif

#endif /* HSE_PLATFORM_PLATFORM_H */
