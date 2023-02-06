/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_PLATFORM_H
#define HSE_PLATFORM_PLATFORM_H

#include <stdint.h>

#include <hse/util/base.h>
#include <hse/util/arch.h>
#include <hse/error/merr.h>

/* MTF_MOCK_DECL(platform) */

/* Threads about to block or enter a long-running operation may
 * set hse_wmesg_tls to indicate their current status.  After
 * returning from the operation they should set it to "-".
 * The message should reside in global memory.
 */
extern thread_local const char * volatile hse_wmesg_tls;

static HSE_ALWAYS_INLINE int
hse_nanosleep(const struct timespec *req, struct timespec *rem, const char *wmesg)
{
    int rc;

    assert(wmesg);
    hse_wmesg_tls = wmesg;

    rc = clock_nanosleep(CLOCK_MONOTONIC, 0, req, rem);

    hse_wmesg_tls = "-";
    return rc;
}

/**
 * hse_readfile() - read a file into a buffer
 * @dirfd: ignored if path is absolute
 * @path:  pathname to file
 * @buf:   dest buffer for file data
 * @bufsz: dest buffer size
 * @flags: open(2) flags
 *
 * This function is intended to provide the same semantics as the
 * proposed readfile(2) system call on Linux.  Reads at most %bufsz
 * bytes from the file specified by %path into %buf.
 *
 * Return: On success, returns the lesser of %bufsz or the number
 * of bytes in the file.  On error, returns -1 and sets errno.
 *
 * https://git.kernel.org/pub/scm/linux/kernel/git/gregkh/driver-core.git/diff/?h=readfile
 *
 * [HSE_REVISIT] Replace with Linux's readfile(2) if/when it comes
 * into existance.
 */
ssize_t
hse_readfile(int dirfd, const char *path, void *buf, size_t bufsz, int flags);

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
 * hse_tsc_mult represents nanoseconds-per-cycle multiplied by 2^hse_tsc_shift
 * to scale it up to an integer with a reasonable number of significant digits.
 * Conversion from cycles to nanoseconds then requires only a multiplication
 * by hse_tsc_mult and a division by 2^hse_tsc_shift (i.e., the division
 * reduces to a simple shift by hse_tsc_shift).
 */
#define HSE_TSC_SHIFT   (21u)

extern volatile unsigned long hse_tsc_freq;
extern volatile unsigned int hse_tsc_mult;

static HSE_ALWAYS_INLINE uint64_t
cycles_to_nsecs(uint64_t cycles)
{
    return ((__uint128_t)cycles * hse_tsc_mult) >> HSE_TSC_SHIFT;
}

extern const char *hse_progname;

extern merr_t hse_platform_init(void);
extern void hse_platform_fini(void);

#if HSE_MOCKING
#include "platform_ut.h"
#endif

#endif /* HSE_PLATFORM_PLATFORM_H */
