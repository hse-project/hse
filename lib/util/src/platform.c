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

#include <hse/version.h>

#include "logging_impl.h"
#include "logging_util.h"
#include "rest_dt.h"

#include <syscall.h>

struct hse_cputopo *hse_cputopov HSE_READ_MOSTLY;
uint hse_cputopoc HSE_READ_MOSTLY;

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

/**
 * hse_scanfile() - extract parameters from a file
 * @file:  name of file to read
 * @fmt:   format for vfscanf
 *
 * Return: Number of items converted, or EOF if file couldn't be
 * opened and/or there was a matching failure.  Sets errno if
 * there was an error.
 */
static int
hse_scanfile(const char *file, const char *fmt, ...)
{
    int saved = 0, n = EOF;
    va_list ap;
    FILE *fp;

    if (!file || !fmt) {
        errno = EINVAL;
        return EOF;
    }

    fp = fopen(file, "r");
    if (fp) {
        va_start(ap, fmt);
        n = vfscanf(fp, fmt, ap);
        if (n == EOF)
            saved = errno;
        va_end(ap);

        fclose(fp);
    }

    if (saved)
        errno = saved;

    return n;
}

static merr_t
hse_cputopo_rest_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    char buf[128];
    int n, i;

    n = snprintf(buf, sizeof(buf), "%4s %4s %4s\n",
                 "vCPU", "CORE", "NODE");
    rest_write_safe(info->resp_fd, buf, n);

    for (i = 0; i < hse_cputopoc; ++i) {
        n = snprintf(buf, sizeof(buf), "%4u %4u %4u\n",
                     i, hse_cpu2core(i), hse_cpu2node(i));
        rest_write_safe(info->resp_fd, buf, n);
    }

    return 0;
}

/**
 * hse_cputopo_init() - build a CPU topology map
 *
 * This function builds a map of the CPU topology such that we can get the
 * calling thread's current CPU, node, and core IDs by calling hse_getcpu().
 */
static merr_t
hse_cputopo_init(void)
{
    uint vcpu_online, core0_count, vcpu, nodemin, nodemax, nodeX;
    size_t align, setszmax, setsz, sz;
    int setcntmax, setcnt, rc, n, i;
    cpu_set_t *omask, *nmask;
    bool restore = false;
    char *bufptr = NULL;
    char file[128];
    u64 tstart;
    merr_t err;

    tstart = get_time_ns();

    setcntmax = 1 << 20; /* max bits in struct hse_cputopo.core */
    nodemax = 1 << 16; /* max bits in struct hse_cputoopo.node */

    setcnt = roundup(get_nprocs_conf(), 64);
    if (setcnt > setcntmax)
        return merr(EINVAL);

    setszmax = CPU_ALLOC_SIZE(setcntmax);

    omask = CPU_ALLOC(setcntmax);
    nmask = CPU_ALLOC(setcntmax);
    if (!omask || !nmask) {
        CPU_FREE(omask);
        CPU_FREE(nmask);
        return merr(ENOMEM);
    }

    CPU_ZERO_S(setszmax, omask);
    CPU_ZERO_S(setszmax, nmask);

    /* sysfs may not be available, so we leverage getaffinity which will fail
     * until we give it a set size large enough for all possible configured
     * CPUs known to the kernel.  This approach allows us to construct a
     * sufficiently and minimally sized hse_cputopov[] such that no bounds
     * checking is required when indexing by any "possible" vCPU ID.
     */
    while (1) {
        setsz = CPU_ALLOC_SIZE(setcnt);

        rc = pthread_getaffinity_np(pthread_self(), setsz, omask);
        if (!rc)
            break;

        if ((setcnt *= 2) >= setcntmax)
            return merr(EINVAL);
    }

    sz = sizeof(*hse_cputopov) * setcnt;
    align = SMP_CACHE_BYTES * 2;

    hse_cputopov = aligned_alloc(align, roundup(sz, align));
    if (!hse_cputopov) {
        CPU_FREE(omask);
        CPU_FREE(nmask);
        return merr(ENOMEM);
    }

    hse_cputopoc = setcnt;

    /* Here we probe sysfs to find the min/max nodes that have CPUs.
     * If the probe fails and/or sysfs isn't available then we'll
     * probe for nodes using the setaffinity/getcpu method (below).
     */
    nodemax = nodeX = 0;

    n = hse_scanfile("/sys/devices/system/node/has_cpu", "%u%ms", &nodemin, &bufptr);
    if (n < 1) {
        nodemin = UINT_MAX;
    } else {
        nodemax = nodeX = nodemin;

        if (n > 1) {
            char *comma = strrchr(bufptr, ',');
            char *dash = strrchr(bufptr, '-');
            char *p;

            p = (dash > comma) ? dash : comma;
            if (p)
                nodemax = strtoul(p + 1, NULL, 0);

            free(bufptr);
        }
    }

    /* Finally, we probe for all possible CPUs (including those not
     * indicated in the original affinity mask).
     */
    vcpu = raw_smp_processor_id();
    vcpu_online = core0_count = 0;

    for (i = 0; i < setcnt; ++i) {
        const char *cpu_core_fmt = "/sys/devices/system/cpu/cpu%u/topology/core_id";
        uint cpuid, nodeid, coreid;

        CPU_CLR_S(vcpu, setsz, nmask);
        vcpu = (vcpu + 1) % setcnt;

        hse_cputopov[vcpu].core = vcpu;

        for (nodeid = nodemin; nodeid <= nodemax; ++nodeid) {
            const char *cpu_node_fmt = "/sys/devices/system/cpu/cpu%u/node%u";

            snprintf(file, sizeof(file), cpu_node_fmt, vcpu, nodeX);

            if (0 == access(file, X_OK)) {
                hse_cputopov[vcpu].node = nodeX;
                ev(1);
                break;
            }

            nodeX = (nodeX + 1) % (nodemax + 1);
            ev(1);
        }

        if (ev(nodeid > nodemax)) {
            CPU_SET_S(vcpu, setsz, nmask);

            rc = pthread_setaffinity_np(pthread_self(), setsz, nmask);
            if (ev(rc))
                continue; /* cpu offline or inaccessible */

            if (0 == syscall(SYS_getcpu, &cpuid, &nodeid, NULL)) {
                hse_cputopov[cpuid].core = cpuid;
                hse_cputopov[cpuid].node = nodeid;
                ev(cpuid != vcpu);
            }

            restore = true;
        }

        /* Core ID is architecture and platform dependent.  It is not
         * the logical core as is typically shown by 'lscpu -p'.  If
         * sysfs isn't configured then scanfile will fail and we'll
         * fall back to using the CPU ID for the core ID.
         */
        snprintf(file, sizeof(file), cpu_core_fmt, vcpu);

        n = hse_scanfile(file, "%u", &coreid);
        if (n == 1) {
            hse_cputopov[vcpu].core = coreid;
            core0_count += (coreid == 0);
        }

        ++vcpu_online;
    }

    if (restore) {
        rc = pthread_setaffinity_np(pthread_self(), setsz, omask);
        if (rc) {
            err = merr(rc); /* this should never happen */
            hse_elog(HSE_WARNING "%s: unable to restore affinity mask: @@e", err, __func__);
        }
    }

    /* If all the vCPUs are on core zero then we might be running in a VM.
     * In this case, use the vCPU ID as the core ID so that our algorithms
     * that map cores to buckets distribute the work over all buckets.
     */
    if (vcpu_online > 2 && vcpu_online == core0_count) {
        for (i = 0; i < setcnt; ++i) {
            hse_cputopov[i].core = i;
        }
    }

    hse_log(HSE_NOTICE "%s: online cpus %u, cpu nodes %u-%u, core0 cpus %u, %lu us",
            __func__, vcpu_online, nodemin, nodemax, core0_count,
            (get_time_ns() - tstart) / 1000);

    CPU_FREE(omask);
    CPU_FREE(nmask);

    return 0;
}

static void
hse_cputopo_fini(void)
{
    free(hse_cputopov);
}

void
hse_cpufreq_init(void)
{
    char linebuf[1024];
    double bogomips;
    int n = EOF;
    FILE *fp;

    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        while (fgets(linebuf, sizeof(linebuf), fp)) {
            n = sscanf(linebuf, "bogomips%*[^0-9]%lf", &bogomips);
            if (n == 1)
                break;
        }

        fclose(fp);
    }

    if (n != 1) {
        hse_log(HSE_WARNING "%s: unable to determine cpu frequency", __func__);
        bogomips = 1000;
    }

    hse_tsc_freq = (bogomips * 1000000) / 2;
    hse_tsc_shift = 21;
    hse_tsc_mult = (NSEC_PER_SEC << hse_tsc_shift) / hse_tsc_freq;

    hse_log(HSE_NOTICE "%s: freq %lu, shift %u, mult %u",
            __func__, hse_tsc_freq, hse_tsc_shift, hse_tsc_mult);
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

    err = hse_cputopo_init();
    if (err)
        goto errout;

    hse_cpufreq_init();

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
    rest_url_register(0, 0, hse_cputopo_rest_get, NULL, "cputopo");
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
    hse_cputopo_fini();
    dt_fini();
    hse_logging_fini();
}

#if HSE_MOCKING
#include "platform_ut_impl.i"
#endif
