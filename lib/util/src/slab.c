/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_slab

/* This file implements a userland version of the Linux kernel's kmem_cache
 * facility.  The primary challenge in userland is correlating a given memory
 * address to the slab from which it was allocated.  This is done efficiently
 * in the kernel via information kept in the struct page.  For userland, we
 * must take a different approach.  Of course, we could keep each allocated
 * address in a tree or hash table or some such, but that is likely to consume
 * extra memory and add many more cycles to the alloc and free paths.
 *
 * So what this implementation does is introduce the concept of a chunk.  A
 * chunk is a virtually contiguous piece of memory that is 2MB in size, 2MB
 * aligned, and affined to the NUMA node from which is was allocated.  Given
 * this, the chunk from which a memory address was allocated can be determined
 * in constant time via simple bit masking of the address.
 *
 * A chunk is then divided into 64 32KB slabs.  The last slab in the chunk
 * is slightly smaller to make room for the chunk header at the end of the
 * chunk.  Slabs are allocated to per-CPU buckets as needed, and returned to
 * the chunk when they become empty.  Individual allocations (i.e., items)
 * are then allocated directly from slabs (e.g., via kmem_cache_alloc()).
 * As a practical matter, a slab may be divided up into at most 1024 items,
 * which means that memory is wasted for allocation sizes below 32 bytes.
 *
 * In general, the large size of the chunk and relatively small size of the
 * chunk header means that for typical allocation sizes the maximum potential
 * memory overhead is well less than 0.8 percent.
 */

#include <stdalign.h>

#include <hse_util/arch.h>
#include <hse_util/alloc.h>
#include <hse_util/atomic.h>
#include <hse_util/assert.h>
#include <hse_util/event_counter.h>

#include <hse_util/mutex.h>
#include <hse_util/spinlock.h>
#include <hse_util/timing.h>
#include <hse_util/minmax.h>
#include <hse_util/string.h>
#include <hse_util/workqueue.h>
#include <hse_util/rest_api.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>

#define MAX_NUMNODES 4

/* KMC_SPC              number of slabs per chunk (power of 2)
 * KMC_SLAB_SZ          slab size in bytes (power of 2)
 * KMC_CHUNK_SZ         chunk size in bytes (power of 2)
 * KMC_CHUNK_MASK       mask used to obtain chunk base address
 * KMC_CHUNK_OFFSET     offset from chunk base to chunk header
 */
#define KMC_SPC             (8)
#define KMC_SLAB_SZ         (256 * 1024)
#define KMC_CHUNK_SZ        (KMC_SPC * KMC_SLAB_SZ)
#define KMC_CHUNK_MASK      (~(KMC_CHUNK_SZ - 1))
#define KMC_CHUNK_OFFSET    (KMC_CHUNK_SZ - sizeof(struct kmc_chunk))

#define KMC_PCPU_MIN        (1)
#define KMC_PCPU_MAX        (16)

#define kmc_slab_first(_head)   list_first_entry_or_null((_head), struct kmc_slab, slab_entry)
#define kmc_slab_last(_head)    list_last_entry_or_null((_head), struct kmc_slab, slab_entry)

#define kmc_slab_foreach(_slab, _next, _head) \
    list_for_each_entry_safe ((_slab), (_next), (_head), slab_entry)

#define kmc_zone_foreach(_zone, _next, _head) \
    list_for_each_entry_safe ((_zone), (_next), (_head), zone_entry)

#define kmc_chunk_first(_head) list_first_entry_or_null((_head), struct kmc_chunk, ch_entry)

#define kmc_chunk_last(_head) list_last_entry_or_null((_head), struct kmc_chunk, ch_entry)

struct kmc_pcpu;
struct kmc_zone;

/**
 * struct kmc_slab - per-cpu affinied contiguous piece of memory
 * @slab_entry:     kmc_node list linkage (partial, full, empty)
 * @slab_list:      ptr to head of list which contains slab_entry
 * @slab_chunk:     ptr to the chunk from which this slab came
 * @slab_pcpu:      ptr to this slabs per-cpu management object
 * @slab_base:      ptr to the base memory address of the slab
 * @slab_zentry:    kmem_cache zone linkage
 * @slab_expired:   true if slab has been empty for a while
 * @slab_bmidx:     bitmap index for next allocation
 * @slab_imax:      max number of items in the slab
 * @slab_iused:     current number of items in use
 * @slab_zalloc:    number of calls to kmem_cache_alloc() on this slab
 * @slab_zfree:     number of calls to kmem_cache_free() on this slab
 * @slab_magic:     used to detect access to invalid slab
 * @slab_bitmap:    bitmap of free items within the slab
 *
 * A slab is a 64KB contiguous piece of virtual memory aligned on a 64KB
 * boundary from which some number of items may be allocated.  The maximum
 * number of items is limited to 1024 (the size of the bitmap), but the
 * actual limit is limited to however many items of a given item size and
 * alignment will fit into the slab.  Slabs are affined to a per-cpu bucket
 * when they are allocated, and remain affined until the last item is freed.
 */
struct kmc_slab {
    struct list_head  slab_entry;
    struct list_head *slab_list;
    struct kmc_chunk *slab_chunk;
    struct kmc_pcpu  *slab_pcpu;
    void *            slab_base;
    struct list_head  slab_zentry;

    bool  slab_expired  HSE_ALIGNED(SMP_CACHE_BYTES);
    uint  slab_bmidx;
    uint  slab_imax;
    uint  slab_iused;
    ulong slab_zalloc;
    ulong slab_zfree;
    void *slab_magic;
    u8    slab_bitmap[sizeof(long) * 16];
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

/**
 * struct kmc_node - perf-numa-node chunk management
 * @node_lock:      protects all node_* fields
 * @node_nchunks:   total number of chunks allocated to this node
 * @node_partial:   list of chunks with one or more free slabs
 * @node_full:      list of chunks with no free slabs
 *
 * A node is a cache of NUMA-node affined chunks of memory.
 * In practice, NUMA-node affinity is not guaranteed.
 */
struct kmc_node {
    spinlock_t       node_lock;
    uint             node_nchunks;
    struct list_head node_partial;
    struct list_head node_full;
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

/**
 * struct kmc_chunk - per-numa node affined chunk of memory
 * @ch_magic:   used for sanity checking
 * @ch_hugecnt: number of huge pages used by this chunk
 * @ch_used:    number of slabs in use from this chunk
 * @ch_max:     total number of slabs in the chunk
 * @ch_entry:   list linkage for node_partial/node_full
 * @ch_slabs:   list of free slabs
 * @ch_node:    ptr to node which manages this chunk
 * @ch_slabv:   vector of slab headers
 *
 * A chunk of memory is a 2MB contiguous piece of virtual memory
 * aligned on a 2MB boundary from which 32 32KB slabs are allocated.
 * A chunk is affined to a NUMA node, and its slabs may be allocate
 * and affined only to CPUs local to that node.
 * In practice, NUMA-node affinity is not guaranteed.
 */
struct kmc_chunk {
    void *           ch_magic;
    int              ch_hugecnt;
    int              ch_used;
    int              ch_max;
    struct list_head ch_entry;
    struct list_head ch_slabs;
    struct kmc_node *ch_node;
    void *           ch_base;
    size_t           ch_basesz;
    struct kmc_slab  ch_slabv[KMC_SPC];
};

/**
 * struct kmc_pcpu - per-cpu slab management lists
 * @pcpu_lock:      protects all list accesses
 * @pcpu_partial:   list of slabs with one or more free items
 * @pcpu_empty:     list of slabs with all items free
 * @pcpu_full:      list of slabs with no items free
 *
 * Per-cpu buckets contain three lists of slabs affined to a given
 * set of CPUS.  Empty slabs that have not been recently allocated
 * from are removed from the bucket and returned to their chunk by
 * the reaper.
 */
struct kmc_pcpu {
    spinlock_t       pcpu_lock;
    struct list_head pcpu_partial;
    struct list_head pcpu_empty;
    struct list_head pcpu_full;
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

/**
 * struct kmem_cache - a zone of uniformly sized parcels of memory
 * @zone_pcpuc:         count of per-cpu objects (zone_pcpuv[])
 * @zone_isize:         caller specified item size
 * @zone_iasz:          item size aligned to zone_item_align
 * @zone_ialign:        caller specified item alignemnt
 * @zone_chunk_maxk;    chunk base memory address mask
 * @zone_delay;         reaper deamon delay
 * @zone_ctor;          item constructor
 * @zone_magic;         used to detect errant access
 * @zone_lock;          protects list and variable accesses that follow
 * @zone_nslabs;        number of slabs in use by this cache
 * @zone_slabs;         list of slabs in use by this cache
 * @zone_zalloc;        total calls to kmem_cache_alloc on this zone
 * @zone_zfree;         total calls to kmem_cache_free on this zone
 * @zone_salloc;        total slab allocations on this zone
 * @zone_sfree;         total slab free on this zone
 * @zone_name;          kmem cache name
 * @zone_node;          vector of per-numa nodes objects
 * @zone_entry;         linkage on global cache list
 * @zone_dwork;         dwork for periodic zone reaping
 * @zone_pcpuv;         per-cpu slab management
 */
struct kmem_cache {
    uint zone_pcpuc;
    uint zone_isize;
    uint zone_ialign;
    uint zone_iasz;
    int  zone_delay;
    void (*zone_ctor)(void *);
    void *zone_magic;

    HSE_ALIGNED(SMP_CACHE_BYTES * 2)
    spinlock_t       zone_lock;
    uint             zone_nslabs;
    struct list_head zone_slabs;
    ulong            zone_zalloc;
    ulong            zone_zfree;
    ulong            zone_salloc;
    ulong            zone_sfree;
    char             zone_name[24];

    struct list_head    zone_entry;
    struct delayed_work zone_dwork;

    struct kmc_pcpu zone_pcpuv[];
};

/**
 * struct kmc - kmem cache globals
 */
static struct {
    struct kmem_cache       *kmc_pagecache;
    struct workqueue_struct *kmc_wq;
    atomic_t                 kmc_huge_used;
    uint                     kmc_huge_max;

    HSE_ALIGNED(SMP_CACHE_BYTES)
    struct mutex     kmc_zone_lock;
    struct list_head kmc_zones;
    int              kmc_nzones;

    struct kmc_node kmc_nodev[MAX_NUMNODES];
} kmc;

static void
kmc_reaper(struct work_struct *work);

static HSE_ALWAYS_INLINE void
kmc_node_lock(struct kmc_node *node)
{
    spin_lock(&node->node_lock);
}

static HSE_ALWAYS_INLINE void
kmc_node_unlock(struct kmc_node *node)
{
    spin_unlock(&node->node_lock);
}

static HSE_ALWAYS_INLINE void
kmem_cache_lock(struct kmem_cache *zone)
{
    spin_lock(&zone->zone_lock);
}

static HSE_ALWAYS_INLINE void
kmem_cache_unlock(struct kmem_cache *zone)
{
    spin_unlock(&zone->zone_lock);
}

static HSE_ALWAYS_INLINE void
kmc_pcpu_lock(struct kmc_pcpu *pcpu)
{
    spin_lock(&pcpu->pcpu_lock);
}

static HSE_ALWAYS_INLINE void
kmc_pcpu_unlock(struct kmc_pcpu *pcpu)
{
    spin_unlock(&pcpu->pcpu_lock);
}

struct kmc_chunk *
kmc_chunk_create(struct kmem_cache *zone, struct kmc_node *node)
{
    struct kmc_chunk *chunk;
    struct kmc_slab * slab;

    int    flags = MAP_ANON | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE;
    int    prot = PROT_READ | PROT_WRITE;
    size_t chunksz, slabsz, hugesz, basesz;
    void * base, *mem;
    int    hugecnt;
    int    i;

    slabsz = KMC_SLAB_SZ;
    chunksz = KMC_CHUNK_SZ;
    hugesz = 2 * 1024 * 1024;
    basesz = chunksz;
    hugecnt = 0;

    if (IS_ALIGNED(chunksz, hugesz)) {
        hugecnt = chunksz / hugesz;
        if (atomic_add_return(hugecnt, &kmc.kmc_huge_used) > kmc.kmc_huge_max) {
            atomic_sub(hugecnt, &kmc.kmc_huge_used);
            hugecnt = 0;
        }
    }

    /* Try to get a huge-page backed address space, if possible.
     */
    if (hugecnt > 0) {
        base = mem = mmap(NULL, chunksz, prot, flags, -1, 0);
        if (base != MAP_FAILED) {
            if (IS_ALIGNED((uintptr_t)base, chunksz))
                goto chunk_init;

            munmap(base, chunksz);
        }

        atomic_sub(hugecnt, &kmc.kmc_huge_used);
        hugecnt = 0;
    }

    /* Otherwise, try to create a suitably aligned address space.
     */
    flags &= ~MAP_HUGETLB;

    base = mmap(NULL, chunksz * 2, prot, flags, -1, 0);
    if (ev(base == MAP_FAILED))
        return NULL;

    mem = PTR_ALIGN(base, chunksz);
    basesz = (size_t)(mem - base) + chunksz;

    /* Trim the excess VMAs from the chunk.
     */
    if (mremap(base, chunksz * 2, basesz, 0) != base) {
        munmap(base, chunksz * 2);
        ev(1);
        return NULL;
    }

    /* [HSE_REVISIT] If base is not chunk aligned then we'll waste the
     * VMA range from base to mem.  In practice, it's typically only a
     * few pages, but occassionally it's hundreds of pages.  We should
     * revisit when we have a better solution and/or we start running
     * into VMA fragmentation issues.  For now, we just protect the
     * range to catch any buggy code that tries to access it.
     */
    if (ev(mem > base))
        mprotect(base, (size_t)(mem - base), PROT_NONE);
    ev(1);

    /* Initialize the chunk header, which is placed at the end
     * of the chunk.
     */
  chunk_init:
    chunk = mem + chunksz - sizeof(*chunk);
    chunk->ch_magic = chunk;
    chunk->ch_hugecnt = hugecnt;
    chunk->ch_node = node;
    chunk->ch_base = base;
    chunk->ch_basesz = basesz;
    INIT_LIST_HEAD(&chunk->ch_slabs);

    /* Initialize each slab header within the chunk header.
     */
    for (i = 0; i < KMC_SPC; ++i) {
        slab = chunk->ch_slabv + i;
        slab->slab_chunk = chunk;
        slab->slab_base = (char *)mem + i * slabsz;
        slab->slab_magic = slab;

        assert(slab->slab_base < (void *)chunk);

        list_add(&slab->slab_entry, &chunk->ch_slabs);
    }

    chunk->ch_max = i;

    return chunk;
}

void
kmc_chunk_destroy(struct kmc_chunk *chunk)
{
    if (!chunk)
        return;

    assert(chunk->ch_magic == chunk);
    chunk->ch_magic = (void *)0xdeadbeef;
    atomic_sub(chunk->ch_hugecnt, &kmc.kmc_huge_used);

    munmap(chunk->ch_base, chunk->ch_basesz);
}

static void
kmc_slab_mprotect(struct kmc_slab *slab, int prot)
{
#if HSE_MOCKING || USE_EFENCE
    size_t slabsz = KMC_SLAB_SZ;
    size_t sz;

    if (slabsz < PAGE_SIZE)
        return;

    sz = (uintptr_t)slab->slab_chunk - (uintptr_t)slab->slab_base;
    sz = sz & ~(PAGE_SIZE - 1);
    if (sz > slabsz)
        sz = slabsz;

    mprotect(slab->slab_base, sz, prot);
#endif
}

struct kmc_slab *
kmc_slab_alloc(struct kmem_cache *zone, uint nodeid)
{
    struct kmc_chunk *chunk;
    struct kmc_slab  *slab;
    struct kmc_node  *node;
    char             *item;
    int i;

    node = kmc.kmc_nodev + (nodeid % NELEM(kmc.kmc_nodev));

    kmc_node_lock(node);
    chunk = kmc_chunk_first(&node->node_partial);
    if (!chunk) {
        kmc_node_unlock(node);

        chunk = kmc_chunk_create(zone, node);
        if (!chunk)
            return NULL;

        kmc_node_lock(node);
        list_add_tail(&chunk->ch_entry, &node->node_partial);
        chunk = kmc_chunk_first(&node->node_partial);
        ++node->node_nchunks;
    }

    slab = kmc_slab_first(&chunk->ch_slabs);
    assert(slab);

    list_del(&slab->slab_entry);

    if (++chunk->ch_used >= chunk->ch_max) {
        list_del(&chunk->ch_entry);
        list_add(&chunk->ch_entry, &node->node_full);
    }
    kmc_node_unlock(node);

    slab->slab_magic = slab;
    slab->slab_expired = false;
    slab->slab_bmidx = 0;
    slab->slab_zalloc = 0;
    slab->slab_zfree = 0;

    assert(slab->slab_iused == 0);
    assert(slab->slab_chunk == chunk);

    slab->slab_imax = KMC_SLAB_SZ / zone->zone_iasz;

    /* If the slab end overlaps or abuts the chunk header then reduce
     * the number of items such that there's no overlap.
     * This must be the last slab in the chunk.
     */
    if (slab->slab_base + KMC_SLAB_SZ >= (void *)chunk) {
        size_t sz = (uintptr_t)chunk - (uintptr_t)slab->slab_base;

        slab->slab_imax = sz / zone->zone_iasz;
    }

    if (slab->slab_imax > sizeof(slab->slab_bitmap) * CHAR_BIT)
        slab->slab_imax = sizeof(slab->slab_bitmap) * CHAR_BIT;

    kmc_slab_mprotect(slab, PROT_READ | PROT_WRITE);

    memset(slab->slab_bitmap, 0, sizeof(slab->slab_bitmap));

    for (i = 0; i < slab->slab_imax; ++i) {
        setbit(slab->slab_bitmap, i);
        if (!zone->zone_ctor)
            continue;

        item = (char *)slab->slab_base + i * zone->zone_iasz;
        zone->zone_ctor(item);
    }

    kmem_cache_lock(zone);
    list_add(&slab->slab_zentry, &zone->zone_slabs);
    ++zone->zone_nslabs;
    ++zone->zone_salloc;
    kmem_cache_unlock(zone);

    return slab;
}

void
kmc_slab_free(struct kmem_cache *zone, struct kmc_slab *slab)
{
    struct kmc_chunk *chunk;
    struct kmc_node * node;

    if (!slab)
        return;

    assert(slab->slab_magic == slab);
    slab->slab_magic = (void *)0xdeadbeef;

    kmc_slab_mprotect(slab, PROT_NONE);

    if (slab->slab_iused > 0) {
        hse_log(
            HSE_ERR "%s: mem leak in zone %s, slab %p, iused %u, max %u",
            __func__,
            zone->zone_name,
            slab,
            slab->slab_iused,
            slab->slab_imax);
        return; /* leak the slab */
    }

    kmem_cache_lock(zone);
    list_del(&slab->slab_zentry);
    zone->zone_zalloc += slab->slab_zalloc;
    zone->zone_zfree += slab->slab_zfree;
    --zone->zone_nslabs;
    ++zone->zone_sfree;
    kmem_cache_unlock(zone);

    chunk = slab->slab_chunk;
    assert(chunk->ch_magic == chunk);

    node = chunk->ch_node;

    kmc_node_lock(node);
    list_add(&slab->slab_entry, &chunk->ch_slabs);

    if (--chunk->ch_used > 0) {
        list_del(&chunk->ch_entry);
        list_add(&chunk->ch_entry, &node->node_partial);
        chunk = NULL;
    } else {
        assert(chunk->ch_used == 0);
        list_del(&chunk->ch_entry);
        --node->node_nchunks;
    }
    kmc_node_unlock(node);

    if (ev(chunk))
        kmc_chunk_destroy(chunk);
}

int
kmc_slab_ffs(struct kmc_slab *slab)
{
    ulong *      map = (ulong *)slab->slab_bitmap;
    const size_t bpl = sizeof(*map) * CHAR_BIT;
    const size_t mapsz = sizeof(slab->slab_bitmap) / sizeof(*map);
    uint         imax, i;

    i = slab->slab_bmidx;
    imax = i + mapsz;

    for (; i < imax; ++i) {
        uint idx = i % mapsz;

        if (map[idx]) {
            slab->slab_bmidx = idx;
            return __builtin_ctzl(map[idx]) + idx * bpl;
        }
    }

    return -1;
}

static HSE_ALWAYS_INLINE struct kmc_pcpu *
kmc_cpu2cache(struct kmem_cache *zone, uint *nodep)
{
    uint cpu, core, n;

    hse_getcpu(&cpu, nodep, &core);

    n = zone->zone_pcpuc / 2;

    return zone->zone_pcpuv + ((*nodep % 2) * n) + (core % n);
}

void *
kmem_cache_alloc(struct kmem_cache *zone)
{
    struct kmc_pcpu *pcpu;
    struct kmc_slab *slab;
    void *           mem;
    int              idx;
    uint node;

    assert(zone);
    assert(zone->zone_magic == zone);

    pcpu = kmc_cpu2cache(zone, &node);

    kmc_pcpu_lock(pcpu);
    while (1) {
        slab = kmc_slab_first(&pcpu->pcpu_partial);
        if (slab)
            break;

        slab = kmc_slab_first(&pcpu->pcpu_empty);
        if (slab) {
            list_del(&slab->slab_entry);
            list_add(&slab->slab_entry, &pcpu->pcpu_partial);
            slab->slab_list = &pcpu->pcpu_partial;
            break;
        }
        kmc_pcpu_unlock(pcpu);

        slab = kmc_slab_alloc(zone, node);

        pcpu = kmc_cpu2cache(zone, &node);

        kmc_pcpu_lock(pcpu);
        if (slab) {
            list_add(&slab->slab_entry, &pcpu->pcpu_empty);
            slab->slab_list = &pcpu->pcpu_empty;
            slab->slab_pcpu = pcpu;
        }
    }

    assert(slab->slab_magic == slab);
    assert(slab->slab_iused < slab->slab_imax);
    assert(slab->slab_chunk->ch_magic == slab->slab_chunk);

    idx = kmc_slab_ffs(slab);

    assert(idx >= 0);
    assert(idx < slab->slab_imax);
    assert(isset(slab->slab_bitmap, idx));

    clrbit(slab->slab_bitmap, idx);
    ++slab->slab_zalloc;

    if (++slab->slab_iused >= slab->slab_imax) {
        list_del(&slab->slab_entry);
        list_add(&slab->slab_entry, &pcpu->pcpu_full);
        slab->slab_list = &pcpu->pcpu_full;
        slab->slab_bmidx = 0;
    }
    kmc_pcpu_unlock(pcpu);

    mem = (char *)slab->slab_base + idx * zone->zone_iasz;

    return mem;
}

void *
kmem_cache_zalloc(struct kmem_cache *zone)
{
    void *mem;

    mem = kmem_cache_alloc(zone);
    if (mem)
        memset(mem, 0, zone->zone_isize);

    return mem;
}


static struct kmc_slab *
kmc_addr2slab(struct kmem_cache *zone, void *mem, uint *idxp)
{
    struct kmc_chunk *chunk;
    struct kmc_slab * slab;
    uintptr_t         addr;
    uintptr_t         idx;

    assert(zone->zone_magic == zone);

    addr = (uintptr_t)mem;
    if (!addr)
        return NULL;

    /* Find the base address of the chunk from the upper bits
     * of the given addr (chunks are always power-of-2 aligned).
     */
    chunk = (struct kmc_chunk *)((addr & KMC_CHUNK_MASK) + KMC_CHUNK_OFFSET);

    if (HSE_UNLIKELY(chunk != chunk->ch_magic)) {
        assert(chunk == chunk->ch_magic);
        abort(); /* invalid free or chunk corruption */
    }

    /* Find the slab within the chunk from the lower bits of the
     * given addr (slabs are always power-of-2 aligned).
     */
    slab = chunk->ch_slabv + ((addr & ~KMC_CHUNK_MASK) / KMC_SLAB_SZ);

    if (HSE_UNLIKELY(slab != slab->slab_magic)) {
        assert(slab == slab->slab_magic);
        abort(); /* invalid free or slab corruption */
    }

    /* Find the index of the item within the slab (items may
     * or may not have power-of-2 alignment).
     */
    idx = (mem - slab->slab_base) / zone->zone_iasz;

    if (HSE_UNLIKELY(idx >= slab->slab_imax)) {
        assert(idx < slab->slab_imax);
        abort(); /* invalid free or slab corruption */
    }

    *idxp = idx;

    return slab;
}

void
kmem_cache_free(struct kmem_cache *zone, void *mem)
{
    struct kmc_slab *slab;
    struct kmc_pcpu *pcpu;
    uint             idx;

    assert(zone);
    assert(zone->zone_magic == zone);

    slab = kmc_addr2slab(zone, mem, &idx);
    if (!slab)
        return;

    assert(slab->slab_magic == slab);

    pcpu = slab->slab_pcpu;

    kmc_pcpu_lock(pcpu);
    assert(isclr(slab->slab_bitmap, idx));
    setbit(slab->slab_bitmap, idx);
    ++slab->slab_zfree;

    if (--slab->slab_iused > 0) {
        if (slab->slab_list != &pcpu->pcpu_partial) {
            list_del(&slab->slab_entry);
            list_add_tail(&slab->slab_entry, &pcpu->pcpu_partial);
            slab->slab_list = &pcpu->pcpu_partial;
        }
    } else {
        if (slab != kmc_slab_first(&pcpu->pcpu_partial)) {
            list_del(&slab->slab_entry);
            list_add(&slab->slab_entry, &pcpu->pcpu_empty);
            slab->slab_list = &pcpu->pcpu_empty;
            slab->slab_expired = false;
        }
    }
    kmc_pcpu_unlock(pcpu);
}

static void
kmc_reaper(struct work_struct *work)
{
    struct kmem_cache *zone;
    struct list_head   expired;
    struct kmc_slab   *slab, *next;

    ulong delay;
    int   i;

    zone = container_of(work, struct kmem_cache, zone_dwork.work);
    assert(zone->zone_magic == zone);

    INIT_LIST_HEAD(&expired);

    /* Examine each per-cpu cache and free all slabs that
     * haven't been used since the last time we checked.
     */
    for (i = 0; i < zone->zone_pcpuc; ++i) {
        struct kmc_pcpu *pcpu = zone->zone_pcpuv + i;

        kmc_pcpu_lock(pcpu);
        slab = kmc_slab_first(&pcpu->pcpu_partial);
        if (slab && slab->slab_iused == 0 && slab != kmc_slab_last(&pcpu->pcpu_partial)) {
            list_del(&slab->slab_entry);
            list_add(&slab->slab_entry, &pcpu->pcpu_empty);
            slab->slab_list = &pcpu->pcpu_empty;
            slab->slab_expired = false;
        }

        kmc_slab_foreach(slab, next, &pcpu->pcpu_empty) {
            if (slab->slab_expired) {
                list_del(&slab->slab_entry);
                list_add(&slab->slab_entry, &expired);
                slab->slab_list = NULL;
            }
            slab->slab_expired = true;
        }
        kmc_pcpu_unlock(pcpu);
    }

    kmc_slab_foreach(slab, next, &expired)
        kmc_slab_free(zone, slab);

    if (zone == kmc.kmc_pagecache) {
        for (i = 0; i < MAX_NUMNODES; ++i) {
            struct kmc_node * node = kmc.kmc_nodev + i;
            struct kmc_chunk *chunk;

            kmc_node_lock(node);
            chunk = kmc_chunk_last(&node->node_partial);
            if (chunk) {
                if (chunk->ch_used > 0) {
                    chunk = NULL;
                } else {
                    list_del(&chunk->ch_entry);
                    --node->node_nchunks;
                }
            }
            kmc_node_unlock(node);

            if (ev(chunk))
                kmc_chunk_destroy(chunk);
        }
    }

    delay = msecs_to_jiffies(zone->zone_delay + (get_cycles() % 1024) * 4);
    queue_delayed_work(kmc.kmc_wq, &zone->zone_dwork, delay);
}

struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align, ulong flags, void (*ctor)(void *))
{
    struct kmem_cache *zone;

    size_t slab_sz, zone_sz, iasz;
    uint   pcpuc, i;
    ulong  delay;

    assert(kmc.kmc_wq);

    if (ev(!name || (align & (align - 1))))
        return NULL;

    align = max_t(size_t, align, sizeof(void *) * 2);

    if (flags & SLAB_HWCACHE_ALIGN)
        align = ALIGN(align, SMP_CACHE_BYTES);

    iasz = max_t(size_t, ALIGN(size, align), 8);

    slab_sz = KMC_SLAB_SZ;
    if (iasz > slab_sz / 4)
        return NULL;

    pcpuc = clamp_t(uint, num_conf_cpus(), KMC_PCPU_MIN, KMC_PCPU_MAX);
    zone_sz = sizeof(*zone) + sizeof(zone->zone_pcpuv[0]) * pcpuc;
    zone_sz = ALIGN(zone_sz, alignof(*zone));

    zone = alloc_aligned(zone_sz, alignof(*zone));
    if (ev(!zone))
        return NULL;

    memset(zone, 0, sizeof(*zone));
    zone->zone_pcpuc = pcpuc;
    zone->zone_isize = size;
    zone->zone_iasz = iasz;
    zone->zone_ialign = align;
    zone->zone_ctor = ctor;
    INIT_LIST_HEAD(&zone->zone_slabs);
    zone->zone_delay = 15000;
    zone->zone_magic = zone;

    spin_lock_init(&zone->zone_lock);
    strlcpy(zone->zone_name, name, sizeof(zone->zone_name));

    for (i = 0; i < pcpuc; ++i) {
        struct kmc_pcpu *pcpu = zone->zone_pcpuv + i;

        spin_lock_init(&pcpu->pcpu_lock);
        INIT_LIST_HEAD(&pcpu->pcpu_partial);
        INIT_LIST_HEAD(&pcpu->pcpu_full);
        INIT_LIST_HEAD(&pcpu->pcpu_empty);
    }

    mutex_lock(&kmc.kmc_zone_lock);
    list_add_tail(&zone->zone_entry, &kmc.kmc_zones);
    ++kmc.kmc_nzones;
    mutex_unlock(&kmc.kmc_zone_lock);

    INIT_DELAYED_WORK(&zone->zone_dwork, kmc_reaper);
    delay = msecs_to_jiffies(zone->zone_delay);
    queue_delayed_work(kmc.kmc_wq, &zone->zone_dwork, delay);

    /* Warm up each per-cpu bucket.  This should equitably distribute
     * huge pages across all zones at system start and ensure they can
     * provide an initial minimum of jitter-free allocation requests.
     */
    if (true) {
        cpu_set_t omask, nmask;
        uint cpu;
        void *p;
        int rc;

        /* TODO: Use dynamic cpu sets to accomodate more than 1024 cpus...
         */
        rc = pthread_getaffinity_np(pthread_self(), sizeof(omask), &omask);
        if (rc) {
            hse_log(HSE_ERR "%s: getaffinity failed: zone %s, cpu %u, errno %d",
                    __func__, zone->zone_name, raw_smp_processor_id(), rc);
            goto errout;
        }

        cpu = raw_smp_processor_id();

        for (i = 0; i < CPU_SETSIZE; ++i) {
            cpu = (cpu + 1) % CPU_SETSIZE;

            if (!CPU_ISSET(cpu, &omask))
                continue;

            CPU_ZERO(&nmask);
            CPU_SET(cpu, &nmask);

            rc = pthread_setaffinity_np(pthread_self(), sizeof(nmask), &nmask);
            if (rc) {
                hse_log(HSE_ERR "%s: setaffinity failed: zone %s, cpu %u, errno %d",
                        __func__, zone->zone_name, cpu, rc);
                continue;
            }

            p = kmem_cache_alloc(zone);
            if (p)
                kmem_cache_free(zone, p);
        }

        pthread_setaffinity_np(pthread_self(), sizeof(omask), &omask);
    }

  errout:
    return zone;
}

/*
 * TODO: don't destroy if still active...
 */
void
kmem_cache_destroy(struct kmem_cache *zone)
{
    struct kmc_slab *slab;
    int              i;

    if (ev(!zone))
        return;

    mutex_lock(&kmc.kmc_zone_lock);
    list_del(&zone->zone_entry);
    --kmc.kmc_nzones;
    mutex_unlock(&kmc.kmc_zone_lock);

    while (!cancel_delayed_work(&zone->zone_dwork))
        usleep(1000);

    for (i = 0; i < zone->zone_pcpuc; ++i) {
        struct kmc_pcpu *pcpu = zone->zone_pcpuv + i;

        while ((slab = kmc_slab_first(&pcpu->pcpu_partial))) {
            list_del(&slab->slab_entry);
            kmc_slab_free(zone, slab);
        }

        while ((slab = kmc_slab_first(&pcpu->pcpu_full))) {
            list_del(&slab->slab_entry);
            kmc_slab_free(zone, slab);
        }

        while ((slab = kmc_slab_first(&pcpu->pcpu_empty))) {
            list_del(&slab->slab_entry);
            kmc_slab_free(zone, slab);
        }
    }

    zone->zone_magic = (void *)0xdeadbeef;
    free_aligned(zone);
}

unsigned int
kmem_cache_size(struct kmem_cache *zone)
{
    if (!zone)
        return 0;

    return zone->zone_isize;
}

merr_t
kmem_cache_init(void)
{
    int i;

    if (kmc.kmc_pagecache)
        return 0;

    assert(!(KMC_SLAB_SZ & (KMC_SLAB_SZ - 1)));
    assert(!(KMC_CHUNK_SZ & (KMC_CHUNK_SZ - 1)));

    memset(&kmc, 0, sizeof(kmc));
    mutex_init(&kmc.kmc_zone_lock);
    INIT_LIST_HEAD(&kmc.kmc_zones);
    kmc.kmc_nzones = 0;
    kmc.kmc_huge_max = 128;

    for (i = 0; i < MAX_NUMNODES; ++i) {
        spin_lock_init(&kmc.kmc_nodev[i].node_lock);
        kmc.kmc_nodev[i].node_nchunks = 0;
        INIT_LIST_HEAD(&kmc.kmc_nodev[i].node_partial);
        INIT_LIST_HEAD(&kmc.kmc_nodev[i].node_full);
    }

    kmc.kmc_wq = alloc_workqueue("kmc", 0, 1);
    if (ev(!kmc.kmc_wq))
        return merr(ENOMEM);

    kmc.kmc_pagecache = kmem_cache_create("kvdb_pagecache", PAGE_SIZE, PAGE_SIZE, 0, NULL);

    if (ev(!kmc.kmc_pagecache)) {
        destroy_workqueue(kmc.kmc_wq);
        mutex_destroy(&kmc.kmc_zone_lock);
        kmc.kmc_wq = NULL;
        return merr(ENOMEM);
    }

    return 0;
}

void
kmem_cache_fini(void)
{
    struct kmem_cache *zone, *next;

    if (!kmc.kmc_pagecache)
        return;

    mutex_lock(&kmc.kmc_zone_lock);
    kmc.kmc_pagecache = NULL;
    mutex_unlock(&kmc.kmc_zone_lock);

    kmc_zone_foreach(zone, next, &kmc.kmc_zones)
        kmem_cache_destroy((void *)zone);

    destroy_workqueue(kmc.kmc_wq);
    mutex_destroy(&kmc.kmc_zone_lock);
}

static u64
kmc_test(int which, size_t size, size_t align, void *zone)
{
    u64   itermax = 1024 * 8;
    void *addrv[itermax / 3];
    u64   tstart;
    int   i;

    memset(addrv, 0, sizeof(addrv));
    tstart = get_time_ns();

    for (i = 0; i < itermax; ++i) {
        int idx = i % ARRAY_SIZE(addrv);

        switch (which) {
        case 1:
            free(addrv[idx]);
            addrv[idx] = malloc(size);
            break;

        case 2:
            free(addrv[idx]);
            addrv[idx] = aligned_alloc(align, size);
            break;

        case 3:
            free_aligned(addrv[idx]);
            addrv[idx] = alloc_aligned(size, align);
            break;

        case 4:
            kmem_cache_free(zone, addrv[idx]);
            addrv[idx] = kmem_cache_alloc(zone);
            break;

        default:
            break;
        }
    }

    for (i = 0; i < ARRAY_SIZE(addrv); ++i) {
        switch (which) {
        case 3:
            free_aligned(addrv[i]);
            break;

        case 4:
            kmem_cache_free(zone, addrv[i]);
            break;

        default:
            free(addrv[i]);
            break;
        }
    }

    return (get_time_ns() - tstart) / itermax;
}

static void
kmc_rest_get_test(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    char         buf[128];
    const size_t bufsz = sizeof(buf);
    size_t       sz;
    int          n;

    n = snprintf(buf, sizeof(buf), "%4s %9s %9s %13s %13s %16s\n",
                 "cpu", "size", "malloc", "aligned_alloc", "alloc_aligned", "kmem_cache_alloc");
    rest_write_safe(info->resp_fd, buf, n);

    for (sz = 8; sz < 4u << 20; sz *= 2) {
        size_t align = sz;
        void * zone;
        u64    nspa;

        zone = kmem_cache_create(__func__, sz, align, 0, NULL);

        n = snprintf(buf, bufsz, "%4u %9zu", raw_smp_processor_id(), sz);
        rest_write_safe(info->resp_fd, buf, n);

        nspa = kmc_test(1, sz, align, NULL);
        nspa = kmc_test(1, sz, align, NULL);
        n = snprintf(buf, bufsz, " %9zu",  nspa);
        rest_write_safe(info->resp_fd, buf, n);

        nspa = kmc_test(2, sz, align, NULL);
        nspa = kmc_test(2, sz, align, NULL);
        n = snprintf(buf, bufsz, " %13zu",  nspa);
        rest_write_safe(info->resp_fd, buf, n);

        nspa = kmc_test(3, sz, align, NULL);
        nspa = kmc_test(3, sz, align, NULL);
        n = snprintf(buf, bufsz, " %13zu",  nspa);
        rest_write_safe(info->resp_fd, buf, n);

        if (zone) {
            nspa = kmc_test(4, sz, align, zone);
            nspa = kmc_test(4, sz, align, zone);
            n = snprintf(buf, bufsz, " %16zu",  nspa);
            rest_write_safe(info->resp_fd, buf, n);
            kmem_cache_destroy(zone);
        }

        rest_write_safe(info->resp_fd, "\n", 1);
    }
}

static int
kmc_snprintf(struct kmem_cache *zone, char *buf, size_t bufsz, const char *fmt)
{
    struct list_head *head;
    struct kmc_slab * slab;

    ulong nempty, nchunks;
    ulong zalloc, zfree;
    ulong iused, itotal;
    int   cc, i;

    head = &zone->zone_slabs;
    zalloc = zone->zone_zalloc;
    zfree = zone->zone_zfree;
    nempty = nchunks = 0;
    iused = itotal = 0;

    slab = list_first_entry_or_null(head, struct kmc_slab, slab_zentry);
    while (slab) {
        zalloc += slab->slab_zalloc;
        zfree += slab->slab_zfree;
        itotal += slab->slab_imax;
        iused += slab->slab_iused;
        if (slab->slab_iused == 0)
            ++nempty;

        slab = list_next_entry_or_null(slab, slab_zentry, head);
    }

    for (i = 0; i < MAX_NUMNODES; ++i)
        nchunks += kmc.kmc_nodev[i].node_nchunks;

    cc = snprintf(
        buf,
        bufsz,
        fmt,
        zone->zone_name,
        atomic_read(&kmc.kmc_huge_used),
        nchunks,
        (nchunks * KMC_CHUNK_SZ) / 1024,
        zone->zone_nslabs,
        (KMC_SLAB_SZ * zone->zone_nslabs) / 1024,
        nempty,
        zone->zone_salloc,
        zone->zone_sfree,
        zone->zone_isize,
        zone->zone_ialign,
        itotal,
        iused,
        zalloc,
        zfree);

    return cc;
}

merr_t
kmc_rest_get_vmstat(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    struct kmem_cache *zone, *next;
    const char *       fmt;
    char               buf[256];
    int                n;

    snprintf(
        buf,
        sizeof(buf),
        "%-20s %5s %7s %7s %6s %7s %6s %8s %8s"
        " %7s %7s %9s %9s %13s %13s\n",
        "NAME",
        "NHUGE",
        "NCHUNKS",
        "CHUNKKB",
        "NSLABS",
        "SLABKB",
        "SEMPTY",
        "SALLOC",
        "SFREE",
        "ISIZE",
        "IALIGN",
        "ITOTAL",
        "IUSED",
        "IALLOC",
        "IFREE");

    rest_write_safe(info->resp_fd, buf, strlen(buf));

    fmt = "%-20.20s %5d %7lu %7lu %6u %7u %6lu %8lu %8lu"
          " %7u %7u %9lu %9lu %13lu %13lu\n";

    mutex_lock(&kmc.kmc_zone_lock);
    kmc_zone_foreach(zone, next, &kmc.kmc_zones) {
        n = kmc_snprintf(zone, buf, sizeof(buf), fmt);
        if (n > 0) {
            n = min_t(int, n, sizeof(buf));
            rest_write_safe(info->resp_fd, buf, n);
        }
    }
    mutex_unlock(&kmc.kmc_zone_lock);

    return 0;
}

merr_t
kmc_rest_get(
    const char *      path,
    struct conn_info *info,
    const char *      url,
    struct kv_iter *  iter,
    void *            context)
{
    if (strstr(path, "/vmstat")) {
        kmc_rest_get_vmstat(path, info, url, iter, context);
        return 0;
    }

    if (strstr(path, "/test")) {
        kmc_rest_get_test(path, info, url, iter, context);
        return 0;
    }

    return merr(EINVAL);
}

void *
hse_page_alloc(void)
{
    return kmem_cache_alloc(kmc.kmc_pagecache);
}

void *
hse_page_zalloc(void)
{
    void *mem;

    mem = kmem_cache_alloc(kmc.kmc_pagecache);
    if (mem)
        memset(mem, 0, PAGE_SIZE);

    return mem;
}

void
hse_page_free(void *mem)
{
    kmem_cache_free(kmc.kmc_pagecache, mem);
}

#if HSE_MOCKING
#include "slab_ut_impl.i"
#endif
