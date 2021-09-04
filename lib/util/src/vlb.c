/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/page.h>
#include <hse_util/spinlock.h>
#include <hse_util/event_counter.h>
#include <hse_util/vlb.h>

#define VLB_NODES_MAX       (4) /* max numa nodes */
#define VLB_BPN_MAX         (4) /* max per-cpu buckets per node */

struct vlb_cache {
    spinlock_t  lock;
    int         cnt;
    void       *head;
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

static struct vlb_cache vlbcv[VLB_NODES_MAX * VLB_BPN_MAX];

static struct vlb_cache *
vlb_cpu2cache(void)
{
    uint cpu, node;

    cpu = hse_getcpu(&node);

    return vlbcv + (((node % VLB_NODES_MAX) * VLB_BPN_MAX) + (cpu % VLB_BPN_MAX));
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

    if (ev(!mem)) {
        int flags = MAP_ANON | MAP_PRIVATE;
        int prot = PROT_READ | PROT_WRITE;

        mem = mmap(NULL, sz, prot, flags, -1, 0);
        if (ev(mem == MAP_FAILED))
            return NULL;

        /* Store vlbc's offset from vlbcv into the last page of the buffer.
         * We'll retrieve it in vlb_free() so that we can return the buffer
         * to its original bucket.  We permute the offset to make it a bit
         * more likely to detect corruption (regardlesss, corruption of the
         * offset can never lead to catastrophic failure).
         */
        *(size_t *)(mem + allocsz - PAGE_SIZE) = ~(size_t)(vlb_cpu2cache() - vlbcv);
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

    if (used > allocsz - PAGE_SIZE) {
        munmap(mem, used);
        return;
    }

    if (used > keepsz)
        rc = madvise(mem + keepsz, used - keepsz, MADV_DONTNEED);

    if (!rc) {
        struct vlb_cache *vlbc = vlbcv + ~(*(size_t *)(mem + allocsz - PAGE_SIZE));

        /* This assert exists to track down callers who clobbered the end of the
         * buffer but didn't tell us about it.  The code will work correctly
         * regardless, with a probability of returning the buffer to the wrong
         * bucket if the corrupted offset goes undetected).  If corruption of
         * the offset is detected we simply free the buffer.
         */
        assert(vlbc >= vlbcv && vlbc < vlbcv + NELEM(vlbcv));

        if (vlbc >= vlbcv && vlbc < vlbcv + NELEM(vlbcv)) {
            spin_lock(&vlbc->lock);
            if (vlbc->cnt * keepsz < hse_gparams.gp_vlb_cache_sz / VLB_BPN_MAX) {
                *(void **)mem = vlbc->head;
                vlbc->head = mem;
                vlbc->cnt++;
                mem = NULL;
            }
            spin_unlock(&vlbc->lock);
        }
    }

    if (ev(mem))
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
