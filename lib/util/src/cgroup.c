/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>

#include <mntent.h>

enum cgroup_version {
    CGROUP_VERS_UNKNOWN = 0,
    CGROUP_VERS_1       = 1,
    CGROUP_VERS_2       = 2,
    CGROUP_VERS_NONE    = 3,
};

static enum cgroup_version cgvers = CGROUP_VERS_UNKNOWN;
static const char *cgmntpt;

static int
cgroup_parse_ulong(const char *path, const char *fmt, ulong *result)
{
    char line[128];
    FILE *fp;
    int n = 0;

    *result = 0;

    fp = fopen(path, "r");
    if (!fp)
        return -1;

    while (fgets(line, sizeof(line), fp)) {
        n = sscanf(line, fmt, result);
        if (n == 1)
            break;
    }

    fclose(fp);

    return n;
}

static void
cgroup_version_probe(void)
{
    struct mntent *entry;
    const char *mnttab = "/etc/mtab";
    FILE *fp;

    cgvers = CGROUP_VERS_NONE;

    fp = fopen(mnttab, "r");
    if (!fp)
        return;

    /*
     * Cgroup v1 mount entries has the mount type as "cgroup". The memory controller mount
     * entry is the one that has the "memory" mount option set.
     * Cgroup v2 mount entry has the mount type as "cgroup2".
     * It's also possible to have a hybrid setup with both v1 and v2, however, a controller
     * can be active only in one version.
     */
    while ((entry = getmntent(fp))) {
        if ((0 == strcmp(entry->mnt_type, "cgroup")) && hasmntopt(entry, "memory")) {
            cgvers = CGROUP_VERS_1;
            free((void *)cgmntpt); /* to handle hybrid config */
            cgmntpt = strdup(entry->mnt_dir);
            break;
        } else if (0 == strcmp(entry->mnt_type, "cgroup2")) {
            cgvers = CGROUP_VERS_2;
            cgmntpt = strdup(entry->mnt_dir);
            /* continue for detecting an hybrid config */
        }
    }

    fclose(fp);
}

static bool
cgroup_name_get(char cgname[PATH_MAX])
{
    static const char fmt_cgpath[] = "/proc/%d/cgroup";
    static const char fmt_cgmem_v1[] = "%*d:memory:%s"; /* second field is "memory" */
    static const char fmt_cgmem_v2[] = "%*d::%s";       /* empty second field */
    char buf[PATH_MAX];
    FILE *fp;
    int n = 0;

    snprintf(buf, sizeof(buf), fmt_cgpath, getpid());
    fp = fopen(buf, "r");
    if (!fp)
        return false;

    cgname[0] = '\0';
    while (fgets(buf, sizeof(buf), fp)) {
        n = sscanf(buf, (cgvers == CGROUP_VERS_1) ? fmt_cgmem_v1 : fmt_cgmem_v2, cgname);
        if (n == 1)
            break;
    }
    fclose(fp);

    if (n != 1 || cgname[0] == '\0')
        return false; /* cgroup config not present */

    return true;
}

bool
hse_meminfo_cgroup(unsigned long *freep, unsigned long *availp, unsigned int shift)
{
    static const char fmt_ulong[] = "%lu";
    char buf[PATH_MAX], *cgpath;
    ulong total = 0, used = 0;
    size_t sz;
    int n = 0;
    bool res = false;

    if (!freep && !availp)
        return false;

    if (cgvers == CGROUP_VERS_UNKNOWN)
        cgroup_version_probe();

    if (cgvers == CGROUP_VERS_NONE)
        return false;

    if (!cgroup_name_get(buf))
        return false;

    sz = strlen(cgmntpt) + strlen(buf) + 1;
    cgpath = malloc(sz);
    if (!cgpath)
        return false;
    snprintf(cgpath, sz, "%s%s", cgmntpt, buf);

    /* Determine cgroup mem limit */
    snprintf(buf, sizeof(buf), "%s/memory.%s", cgpath,
             (cgvers == CGROUP_VERS_1) ? "limit_in_bytes" : "max");
    n = cgroup_parse_ulong(buf, fmt_ulong, &total);
    if (n != 1 || total == 0 || total >= (INT64_MAX & PAGE_MASK))
        goto errout;

    /* Determine cgroup mem usage */
    snprintf(buf, sizeof(buf), "%s/memory.%s", cgpath,
             (cgvers == CGROUP_VERS_1) ? "usage_in_bytes" : "current");
    n = cgroup_parse_ulong(buf, fmt_ulong, &used);
    if (n != 1)
        goto errout;

    /* Determine available memory */
    if (availp) {
        static const char fmt_cache_v1[] = "total_cache %lu";
        static const char fmt_cache_v2[] = "file %lu";
        ulong cached, used_woc;

        snprintf(buf, sizeof(buf), "%s/memory.stat", cgpath);
        n = cgroup_parse_ulong(
                buf, (cgvers == CGROUP_VERS_1) ? fmt_cache_v1 : fmt_cache_v2, &cached);
        if (n != 1)
            goto errout;

        used_woc = used - cached; /* exclude file-backed page cache usage */
        if (total < used_woc)
            total = used_woc;

        *availp = (total - used_woc) >> shift;
    }

    /* Determine free memory */
    if (freep) {
        if (total < used)
            total = used;

        *freep = (total - used) >> shift;
    }

    res = true;
    ev(1); /* monitor usage */

errout:
    free(cgpath);

    return res;
}

void
hse_cgroup_fini(void)
{
    free((void *)cgmntpt);
    /* Protect against reading uninitialized memory in hse_meminfo_cgroup() */
    cgmntpt = NULL;
    cgvers = CGROUP_VERS_UNKNOWN;
}
