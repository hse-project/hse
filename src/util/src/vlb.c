/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/vlb.h>

struct vlb_cache {
    spinlock_t  lock;
    void       *head;
    int         cnt;
} __aligned(SMP_CACHE_BYTES * 2);

static struct vlb_cache vlbc;

merr_t
vlb_init(void)
{
    spin_lock_init(&vlbc.lock);
    vlbc.head = NULL;
    vlbc.cnt = 0;

    return 0;
}

void
vlb_fini(void)
{
    void *head;

    spin_lock(&vlbc.lock);
    head = vlbc.head;
    vlbc.head = NULL;
    vlbc.cnt = 0;
    spin_unlock(&vlbc.lock);

    while (head) {
        void *mem = head;

        head = *(void **)head;

        munmap(mem, VLB_ALLOCSZ_MAX);
    }
}

void *
vlb_alloc(size_t sz)
{
    size_t allocsz = VLB_ALLOCSZ_MAX;
    void *mem = NULL;

    if (sz <= allocsz) {
        sz = allocsz;

        spin_lock(&vlbc.lock);
        mem = vlbc.head;
        if (mem) {
            vlbc.head = *(void **)mem;
            vlbc.cnt--;
        }
        spin_unlock(&vlbc.lock);
    }

    if (ev(!mem, HSE_INFO)) {
        int flags = MAP_ANON | MAP_PRIVATE;
        int prot = PROT_READ | PROT_WRITE;

        mem = mmap(NULL, sz, prot, flags, -1, 0);
        if (ev(mem == MAP_FAILED))
            return NULL;
    }

    return ev(mem, HSE_INFO);
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

    if (ev(used > allocsz)) {
        munmap(mem, used);
        return;
    }

    if (ev(used > keepsz))
        rc = madvise(mem + keepsz, used - keepsz, MADV_DONTNEED);

    if (!rc) {
        spin_lock(&vlbc.lock);
        if (vlbc.cnt * keepsz < VLB_CACHESZ_MAX) {
            *(void **)mem = vlbc.head;
            vlbc.head = mem;
            vlbc.cnt++;
            mem = NULL;
        }
        spin_unlock(&vlbc.lock);
    }

    if (ev(mem, HSE_INFO))
        munmap(mem, allocsz);

    ev(1, HSE_INFO);
}

