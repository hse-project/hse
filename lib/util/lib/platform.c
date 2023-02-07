/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#define MTF_MOCK_IMPL_platform

#include <hse/version.h>
#include <hse/logging/logging.h>

#include <hse/ikvdb/hse_gparams.h>

#include <hse/util/data_tree.h>
#include <hse/util/event_counter.h>
#include <hse/util/minmax.h>
#include <hse/util/page.h>
#include <hse/util/perfc.h>
#include <hse/util/platform.h>
#include <hse/util/slab.h>
#include <hse/util/timer.h>
#include <hse/util/vlb.h>

#include "cgroup.h"

volatile unsigned long hse_tsc_freq;
volatile unsigned int hse_tsc_mult;

const char *hse_progname HSE_READ_MOSTLY;

/* Note: The wmesg pointer is volatile, not what it points to...
 */
thread_local const char * volatile hse_wmesg_tls = "-";

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

    ev(1); /* monitor usage, don't call this function too often */

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

    if (PAGE_SIZE != getpagesize()) {
        log_err("compile-time PAGE_SIZE (%lu) != run-time getpagesize (%d)",
            PAGE_SIZE, getpagesize());

        return merr(EINVAL);
    }

    err = hse_cpu_init();
    if (err)
        goto errout;

    err = hse_timer_init();
    if (err)
        goto errout;

    dt_init();
    event_counter_init();

    err = vlb_init();
    if (err)
        goto errout;

    err = perfc_init();
    if (err)
        goto errout;

    err = kmem_cache_init();
    if (err)
        goto errout;

errout:
    if (err)
        log_errx("initialization failed", err);

    return err;
}

void
hse_platform_fini(void)
{
    kmem_cache_fini();
    perfc_fini();
    hse_cgroup_fini();
    vlb_fini();
    dt_fini();
    hse_timer_fini();
}

#if HSE_MOCKING
#include "platform_ut_impl.i"
#endif
