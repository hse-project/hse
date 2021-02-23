/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/vlb.h>

#include <syscall.h>

#define VLB_NODES_MAX       (4) /* max numa nodes */
#define VLB_BPN_MAX         (4) /* max per-cpu buckets per node */

struct vlb_cache {
    spinlock_t  lock;
    void       *head;
    int         cnt;
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

static struct vlb_cache vlbcv[VLB_NODES_MAX * VLB_BPN_MAX];

static struct vlb_cache *
vlb_cpu2cache(void)
{
    uint cpuid, nodeid;

    if (syscall(SYS_getcpu, &cpuid, &nodeid, NULL)) {
        cpuid = raw_smp_processor_id();
        nodeid = cpuid;
    }

    /* TODO: Use core ID in lieu of cpu ID.  Given that we don't have core ID handy
     * we use four buckets per node to improve the chances that (cpuid mod 4) will
     * map to the same core.  If contention becomes a problem then try raising
     * VLB_BPN_MAX to 8.
     */
    return vlbcv + (((nodeid % VLB_NODES_MAX) * VLB_BPN_MAX) + (cpuid % VLB_BPN_MAX));
}

void *
vlb_alloc(size_t sz)
{
    size_t allocsz = VLB_ALLOCSZ_MAX;
    void *mem = NULL;

    if (sz <= allocsz) {
        struct vlb_cache *vlbc = vlb_cpu2cache();

        sz = allocsz;

        spin_lock(&vlbc->lock);
        mem = vlbc->head;
        if (mem) {
            vlbc->head = *(void **)mem;
            vlbc->cnt--;
        }
        spin_unlock(&vlbc->lock);
    }

    if (!mem) {
        int flags = MAP_ANON | MAP_PRIVATE;
        int prot = PROT_READ | PROT_WRITE;

        mem = mmap(NULL, sz, prot, flags, -1, 0);
        if (ev(mem == MAP_FAILED))
            return NULL;
    }

    return mem;
}

void
vlb_free(void *mem, size_t used)
{
    size_t allocsz = VLB_ALLOCSZ_MAX;
    size_t keepsz = VLB_KEEPSZ_MAX;
    int rc = 0;

    if (!mem)
        return;

    assert(IS_ALIGNED((uintptr_t)mem, PAGE_SIZE));

    if (used > allocsz) {
        munmap(mem, used);
        return;
    }

    if (used > keepsz)
        rc = madvise(mem + keepsz, used - keepsz, MADV_DONTNEED);

    if (!rc) {
        struct vlb_cache *vlbc = vlb_cpu2cache();

        spin_lock(&vlbc->lock);
        if (vlbc->cnt * keepsz < VLB_CACHESZ_MAX / VLB_BPN_MAX) {
            *(void **)mem = vlbc->head;
            vlbc->head = mem;
            vlbc->cnt++;
            mem = NULL;
        }
        spin_unlock(&vlbc->lock);
    }

    if (mem)
        munmap(mem, allocsz);
}

merr_t
vlb_init(void)
{
    int i;

    for (i = 0; i < NELEM(vlbcv); ++i)
        spin_lock_init(&vlbcv[i].lock);

    return 0;
}

void
vlb_fini(void)
{
    void *head;
    int i;

    for (i = 0; i < NELEM(vlbcv); ++i) {
        struct vlb_cache *vlbc = vlbcv + i;

        spin_lock(&vlbc->lock);
        head = vlbc->head;
        vlbc->head = NULL;
        vlbc->cnt = 0;
        spin_unlock(&vlbc->lock);

        while (head) {
            void *mem = head;

            head = *(void **)head;

            munmap(mem, VLB_ALLOCSZ_MAX);
        }
    }
}
