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

/*
 * hse_tsc_freq is the measured frequency of the time stamp counter.
 *
 * hse_tsc_mult and hse_tsc_shift are used to quickly convert from
 * cycles to nanoseconds by avoiding division.
 *
 * hse_tsc_shift determines the number of significant digits in the
 * conversion performed by cycles_to_nsecs().
 *
 * tsc_mult represents nanoseconds-per-cycle multiplied by 2^hse_tsc_shift to
 * scale it up to an integer with a reasonable number of significant digits.
 * Conversion from cycles to nanoseconds then requires only a multiplication
 * by hse_tsc_mult and a division by 2^hse_tsc_shift (i.e., the division reduces
 * to a simple shift by hse_tsc_shift).  The multiplication by hse_tsc_mult therefore
 * limits the magnitude of the value that can be converted to 2^(64 - hse_tsc_shift))
 * in order to avoid overflow.  For example, given a TSC frequency of 2.6GHz,
 * the range of cycles_to_nsecs() is limited to 2^43, or about 3383 seconds,
 * which should be good enough for typical latency measurement purposes.
 * To convert values larger than 2^43 simply divide by hse_tsc_freq, which is
 * slower but will not overflow.
 */
extern unsigned long hse_tsc_freq;
extern unsigned int hse_tsc_mult;
extern unsigned int hse_tsc_shift;

static HSE_ALWAYS_INLINE u64
cycles_to_nsecs(u64 cycles)
{
    /* To avoid overflow, cycles is limited to 2^(64 - hse_tsc_shift).
     */
    return (cycles * hse_tsc_mult) >> hse_tsc_shift;
}

extern merr_t hse_platform_init(void);
extern void hse_platform_fini(void);

#if HSE_MOCKING
#include "platform_ut.h"
#endif

#endif /* HSE_PLATFORM_PLATFORM_H */
