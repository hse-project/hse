/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_arch

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/data_tree.h>
#include <hse_util/perfc.h>
#include <hse_util/timer.h>
#include <hse_util/vlb.h>
#include <hse_util/hse_log_fmt.h>

#include <hse/hse_version.h>

#include <hse_util/program_name.h>
#include <hse_util/rest_api.h>
#include <hse_util/slab.h>

#include "logging_impl.h"
#include "logging_util.h"
#include "rest_dt.h"

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

merr_t
hse_platform_init(void)
{
    struct merr_info info;

    char * basename = NULL, *name = NULL;
    merr_t err;

    if (PAGE_SIZE != getpagesize()) {
        fprintf(
            stderr,
            "Compile-time PAGE_SIZE (%lu)"
            " != Run-time getpagesize (%d)",
            PAGE_SIZE,
            getpagesize());

        err = merr(EINVAL);
        goto errout;
    }

    err = hse_logging_init();
    if (err)
        goto errout;

    err = vlb_init();
    if (err)
        goto errout;

    dt_init();
    hse_logging_post_init();
    hse_log_reg_platform();

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

    /* We only need the name pointer, the error is superfluous */
    hse_program_name(&name, &basename);
    hse_log_sync(HSE_NOTICE "%s: version %s, image %s",
        HSE_UTIL_DESC, hse_version, name ?: "unknown");
    free(name);

    return 0;

errout:
    fprintf(
        stderr,
        "%s, version %s: init failed: %s\n",
        HSE_UTIL_DESC,
        hse_version,
        merr_info(err, &info));

    return err;
}

void
hse_platform_fini(void)
{
    rest_destroy();
    kmem_cache_fini();
    perfc_shutdown();
    hse_timer_fini();
    dt_fini();
    vlb_fini();
    hse_logging_fini();
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "arch_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
