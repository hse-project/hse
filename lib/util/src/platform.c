/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_platform

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/data_tree.h>
#include <hse_util/perfc.h>
#include <hse_util/timer.h>
#include <hse_util/vlb.h>
#include <hse_util/hse_log_fmt.h>
#include <hse_util/rest_api.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>

#include <hse/version.h>

#include "logging_impl.h"
#include "logging_util.h"
#include "rest_dt.h"
#include "cgroup.h"

volatile unsigned long hse_tsc_freq;
volatile unsigned int hse_tsc_mult;

const char *hse_progname HSE_READ_MOSTLY;

/* Note: The wmesg pointer is volatile, not what it points to...
 */
thread_local const char * volatile hse_wmesg_tls = "-";

extern rest_get_t workqueue_rest_get;
extern rest_get_t kmc_rest_get;

/* usleep(3) is simple to use but made obsolete by the more cumbersome
 * nanosleep(2).  So we implement our own version built upon nanosleep
 * to leverage its well-known and reliable semantics.
 */
int
usleep(useconds_t usec)
{
    struct timespec req;

    req.tv_nsec = (usec % USEC_PER_SEC) * 1000;
    req.tv_sec = usec / USEC_PER_SEC;

    return hse_nanosleep(&req, NULL, "usleep");
}

ssize_t
hse_readfile(int dirfd, const char *path, void *buf, size_t bufsz, int flags)
{
    ssize_t cc = -1;
    int fd;

    fd = openat(dirfd, path, flags);
    if (fd > 0) {
        ssize_t buflen = 0;
        int xerrno = 0;

        while (buflen < bufsz) {
            cc = read(fd, buf + buflen, bufsz - buflen);
            if (cc <= 0) {
                if (cc < 0) {
                    xerrno = errno;
                    buflen = cc;
                }
                break;
            }

            buflen += cc;
        }

        close(fd);
        cc = buflen;
        errno = xerrno;
    }

    return cc;
}

static inline int
hse_meminfo_cvt(const char *src, ulong *valp)
{
    char *end = NULL;

    errno = 0;
    *valp = strtoul(src, &end, 0);

    if (*valp == ULONG_MAX && errno)
        return 0;

    if (*valp == 0 && end == src)
        return 0;

    assert(end && end[0] == ' ' && end[1] == 'k');

    *valp *= 1024;

    return 1;
}

void
hse_meminfo(ulong *freep, ulong *availp, uint shift)
{
    static const char mf[] = "MemFree:";
    static const char ma[] = "MemAvailable:";
    char buf[256], *str;
    ssize_t cc;

    if (hse_meminfo_cgroup(freep, availp, shift))
        return;

    cc = hse_readfile(-1, "/proc/meminfo", buf, sizeof(buf), O_RDONLY);
    if (cc > 0) {
        buf[cc - 1] = '\000';

        if (freep) {
            str = strstr(buf, mf);
            if (str && hse_meminfo_cvt(str + strlen(mf), freep)) {
                *freep >>= shift;
                freep = NULL;
            }
        }

        if (availp) {
            str = strstr(buf, ma);
            if (str && hse_meminfo_cvt(str + strlen(ma), availp)) {
                *availp >>= shift;
                availp = NULL;
            }
        }

        assert(!freep);
        assert(!availp);
    }

    if (ev(freep))
        *freep = 0;

    if (ev(availp))
        *availp = 0;

    ev(1); /* monitor usage, don't call this function too often */
}

/* For amd64 based machines we use the TSC to measure the latency
 * of various operations, ignoring the fact that it might not be
 * P-state invariant.  We derive the TSC frequency from bogomips
 * to use in conversions from cycles to nanosecs.  bogomips may
 * be inaccurate, however it's accurate enough for our purposes.
 *
 * For s390x based machines we can read the TOD clock cheaply
 * with an apparent resolution of 1000/4096 nanoseconds, which
 * makes for a cheap/fast "cycle counter".
 *
 * If a cheap/fast cycle counter is not available then we default
 * to using clock_gettime() as a generic 1GHz "cycle counter".
 */
static merr_t
hse_cpu_init(void)
{
    char buf[4096], *str;
    int bogomips = 0;
    ssize_t cc;

    cc = hse_readfile(-1, "/proc/cpuinfo", buf, sizeof(buf), O_RDONLY);
    if (cc > 0) {
        buf[cc - 1] = '\000';

        str = strstr(buf, "bogomips");
        if (str) {
            int val, n;

            n = sscanf(str, "bogomips%*[^0-9]%d", &val);
            if (n == 1 && val > 0)
                bogomips = val;
        }
    }

#if __amd64__
    hse_tsc_freq = (bogomips * 1000000ul) / 2; /* get_cycles() uses rdtsc() */
#elif __s390x__
    hse_tsc_freq = 1000000ul * 4096; /* See get_cycles() for s390x in arch.h */
#else
    hse_tsc_freq = 1000000000ul; /* get_cycles() defaults to using get_time_ns() */
#endif

    if (!hse_tsc_freq)
        return merr(ENOENT);

    hse_tsc_mult = (NSEC_PER_SEC << HSE_TSC_SHIFT) / hse_tsc_freq;

    log_info("bogomips %d, freq %lu, shift %u, mult %u, L1D_CLSZ %d",
             bogomips, hse_tsc_freq, HSE_TSC_SHIFT, hse_tsc_mult,
             LEVEL1_DCACHE_LINESIZE);

    return 0;
}

merr_t
hse_platform_init(void)
{
    merr_t err;

    hse_progname = program_invocation_name ?: __func__;

    if (PAGE_SIZE != getpagesize()) {
        fprintf(stderr, "%s: Compile-time PAGE_SIZE (%lu) != Run-time getpagesize (%d)",
                __func__, PAGE_SIZE, getpagesize());

        err = merr(EINVAL);
        goto errout;
    }

    dt_init();
    event_counter_init();

    err = hse_cpu_init();
    if (err)
        goto errout;

    err = hse_timer_init();
    if (err)
        goto errout;

    err = hse_log_init();
    if (err)
        goto errout;

    hse_log_reg_platform();

    err = vlb_init();
    if (err)
        goto errout;

    err = perfc_init();
    if (err)
        goto errout;

    err = kmem_cache_init();
    if (err)
        goto errout;

    rest_init();
    rest_url_register(NULL, 0, rest_dt_get, rest_dt_put, "data"); /* for dt */
    rest_url_register(NULL, 0, kmc_rest_get, NULL, "kmc");
    rest_url_register(NULL, 0, workqueue_rest_get, NULL, "ps");

    log_info_sync("%s: version %s, image %s",
                  HSE_UTIL_DESC, HSE_VERSION_STRING, hse_progname);

errout:
    if (err) {
        struct merr_info info;

        fprintf(stderr, "%s: version %s, image %s: init failed: %s\n",
                HSE_UTIL_DESC, HSE_VERSION_STRING, hse_progname, merr_info(err, &info));
    }

    return err;
}

void
hse_platform_fini(void)
{
    rest_destroy();
    kmem_cache_fini();
    perfc_fini();
    vlb_fini();
    hse_log_fini();
    hse_timer_fini();
    hse_cgroup_fini();
    dt_fini();
}

#if HSE_MOCKING
#include "platform_ut_impl.i"
#endif
