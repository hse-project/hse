/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_platform

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/data_tree.h>
#include <hse_util/perfc.h>
#include <hse_util/timer.h>
#include <hse_util/vlb.h>
#include <hse_util/hse_log_fmt.h>
#include <hse_util/program_name.h>
#include <hse_util/rest_api.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>

#include <hse/version.h>

#include "logging_impl.h"
#include "logging_util.h"
#include "rest_dt.h"
#include "cgroup.h"

#include <syscall.h>

unsigned long hse_tsc_freq HSE_READ_MOSTLY;
unsigned int hse_tsc_mult HSE_READ_MOSTLY;
unsigned int hse_tsc_shift HSE_READ_MOSTLY;

rest_get_t kmc_rest_get;

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
    static const char path[] = "/proc/meminfo";
    static const char mf[] = "MemFree:";
    static const char ma[] = "MemAvailable:";
    static const int  mflen = sizeof(mf) - 1;
    static const int  malen = sizeof(ma) - 1;

    char  line[128];
    FILE *fp;

    if (hse_meminfo_cgroup(freep, availp, shift))
        return;

    fp = fopen(path, "r");
    if (fp) {
        int nmax = !!freep + !!availp;

        while (nmax > 0 && fgets(line, sizeof(line), fp)) {
            if (freep && 0 == strncmp(line, mf, mflen)) {
                nmax -= hse_meminfo_cvt(line + mflen, freep);
                *freep >>= shift;
                freep = NULL;
            } else if (availp && 0 == strncmp(line, ma, malen)) {
                nmax -= hse_meminfo_cvt(line + malen, availp);
                *availp >>= shift;
                availp = NULL;
            }
        }

        assert(nmax == 0);
        fclose(fp);
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
 * If a cheap/fast cycle counter is not available then we default
 * to using clock_gettime() as a generic 1GHz "cycle counter".
 */
static merr_t
hse_cpu_init(void)
{
    int bogomips = 2000;

#if __amd64__
    FILE *fp;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char linebuf[1024];
        int val, n;

        while (fgets(linebuf, sizeof(linebuf), fp)) {
            n = sscanf(linebuf, "bogomips%*[^0-9]%d", &val);
            if (n == 1 && val > 0) {
                bogomips = val;
                break;
            }
        }

        fclose(fp);
    }
#else
    if (-1 == sched_getcpu()) {
        hse_log(HSE_WARNING "%s: getcpu() not supported by this kernel", __func__);
        return merr(ENOTSUP);
    }
#endif

    hse_tsc_freq = (bogomips * 1000000ul) / 2;

    hse_tsc_shift = 21;
    hse_tsc_mult = (NSEC_PER_SEC << hse_tsc_shift) / hse_tsc_freq;

    hse_log(HSE_NOTICE "%s: freq %lu, shift %u, mult %u",
            __func__, hse_tsc_freq, hse_tsc_shift, hse_tsc_mult);

    return 0;
}

merr_t
hse_platform_init(void)
{
    char *basename = NULL, *name = NULL;
    struct merr_info info;
    merr_t err;

    /* We only need the name pointer, the error is superfluous */
    hse_program_name(&name, &basename);

    if (PAGE_SIZE != getpagesize()) {
        fprintf(stderr, "%s: Compile-time PAGE_SIZE (%lu) != Run-time getpagesize (%d)",
                __func__, PAGE_SIZE, getpagesize());

        err = merr(EINVAL);
        goto errout;
    }

    err = hse_logging_init();
    if (err)
        goto errout;

    dt_init();
    hse_logging_post_init();
    hse_log_reg_platform();

    err = hse_cpu_init();
    if (err)
        goto errout;

    err = vlb_init();
    if (err)
        goto errout;

    err = hse_timer_init();
    if (err)
        goto errout;

    err = perfc_init();
    if (err)
        goto errout;

    err = kmem_cache_init();
    if (err)
        goto errout;

    rest_init();
    rest_url_register(0, 0, rest_dt_get, rest_dt_put, "data"); /* for dt */
    rest_url_register(0, 0, kmc_rest_get, NULL, "kmc");

    hse_log_sync(HSE_NOTICE "%s: version %s, image %s",
                 HSE_UTIL_DESC, HSE_VERSION_STRING, name ?: __func__);

errout:
    if (err) {
        fprintf(stderr, "%s: version %s, image %s: init failed: %s\n",
                HSE_UTIL_DESC, HSE_VERSION_STRING, name ?: __func__, merr_info(err, &info));
    }

    free(name);

    return err;
}

void
hse_platform_fini(void)
{
    rest_destroy();
    kmem_cache_fini();
    perfc_shutdown();
    hse_timer_fini();
    vlb_fini();
    dt_fini();
    hse_logging_fini();
    hse_cgroup_fini();
}

#if HSE_MOCKING
#include "platform_ut_impl.i"
#endif
