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
 * A chunk is then divided into 8 256KB slabs.  The last slab in the chunk
 * is slightly smaller to make room for the chunk header at the end of the
 * chunk.  Slabs are allocated to per-CPU buckets as needed, and returned to
 * the chunk when they become empty.  Individual allocations (i.e., items)
 * are then allocated directly from slabs (e.g., via kmem_cache_alloc()).
 */

#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/vlb.h>
#include <hse_util/atomic.h>
#include <hse_util/log2.h>
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

/* clang-format off */

/* KMC_SPC_MAX              max number of slabs per chunk (power of 2)
 * KMC_SLAB_SZ              slab size in bytes (power of 2)
 * KMC_CHUNK_SZ             chunk size in bytes (power of 2)
 * KMC_CHUNK_MASK           mask used to obtain chunk base address
 * KMC_CHUNK_OFFSET         offset from chunk base to chunk header
 * KMC_NODES_MAX            max NUMA nodes to provision
 * KMC_HUGE_MAX             max huge pages to allocate
 * KMC_PCPU_MAX             max number of per-cpu caches per NUMA node
 */
#define KMC_SPC_MAX         (8)
#define KMC_SLAB_SZ         (256ul * 1024)
#define KMC_CHUNK_SZ        (KMC_SPC_MAX * KMC_SLAB_SZ)
#define KMC_CHUNK_MASK      (~(KMC_CHUNK_SZ - 1))
#define KMC_CHUNK_OFFSET    (KMC_CHUNK_SZ - sizeof(struct kmc_chunk))
#define KMC_NODES_MAX       (4)
#define KMC_HUGE_MAX        (256)
#define KMC_PCPU_MAX        (8)

#define kmc_slab_first(_head) \
    list_first_entry_or_null((_head), struct kmc_slab, slab_entry)

#define kmc_slab_last(_head) \
    list_last_entry_or_null((_head), struct kmc_slab, slab_entry)

#define kmc_slab_foreach(_slab, _next, _head) \
    list_for_each_entry_safe((_slab), (_next), (_head), slab_entry)

#define kmc_zone_foreach(_zone, _next, _head) \
    list_for_each_entry_safe((_zone), (_next), (_head), zone_entry)

#define kmc_chunk_first(_head) \
    list_first_entry_or_null((_head), struct kmc_chunk, ch_entry)

#define kmc_chunk_last(_head) \
    list_last_entry_or_null((_head), struct kmc_chunk, ch_entry)

#define kmc_chunk_foreach(_chunk, _next, _head) \
    list_for_each_entry_safe((_chunk), (_next), (_head), ch_entry)

#define kmc_node_lock_init(_node)       mutex_init_adaptive(&(_node)->node_lock)
#define kmc_node_lock_destroy(_node)    mutex_destroy(&(_node)->node_lock)
#define kmc_node_lock(_node)            mutex_lock(&(_node)->node_lock)
#define kmc_node_unlock(_node)          mutex_unlock(&(_node)->node_lock)

#define kmc_zone_lock_init(_zone)       spin_lock_init(&(_zone)->zone_lock)
#define kmc_zone_lock_destroy(_zone)    spin_lock_destroy(&(_zone)->zone_lock)
#define kmc_zone_lock(_zone)            spin_lock(&(_zone)->zone_lock)
#define kmc_zone_unlock(_zone)          spin_unlock(&(_zone)->zone_lock)

#define kmc_pcpu_lock_init(_pcpu)       spin_lock_init(&(_pcpu)->pcpu_lock)
#define kmc_pcpu_lock_destroy(_pcpu)    spin_lock_destroy(&(_pcpu)->pcpu_lock)
#define kmc_pcpu_lock(_pcpu)            spin_lock(&(_pcpu)->pcpu_lock)
#define kmc_pcpu_unlock(_pcpu)          spin_unlock(&(_pcpu)->pcpu_lock)

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
 * @slab_imax:      max number of items in the slab
 * @slab_iused:     current number of items in use
 * @slab_zalloc:    number of calls to kmem_cache_alloc() on this slab
 * @slab_zfree:     number of calls to kmem_cache_free() on this slab
 * @slab_magic:     used to detect access to invalid slab
 *
 * A slab is a 256KB contiguous piece of virtual memory aligned on a 256KB
 * boundary from which some number of items may be allocated.  Slabs are
 * affined to a per-cpu bucket when they are allocated, and remain affined
 * until the last item is freed.
 */
struct kmc_slab {
    struct list_head  slab_entry  HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct list_head  slab_zentry;
    struct kmc_chunk *slab_chunk;
    struct kmc_pcpu  *slab_pcpu;
    void             *slab_base;
    void             *slab_end;

    void             *slab_cache0  HSE_ALIGNED(SMP_CACHE_BYTES);
    void             *slab_cache1;
    uint              slab_icur;
    uint              slab_iused;
    uint              slab_imax;
    bool              slab_expired;
    struct list_head *slab_list;
    ulong             slab_zalloc;
    ulong             slab_zfree;
    void             *slab_magic;
};

/**
 * struct kmc_node - perf-numa-node chunk management
 * @node_lock:      protects all node_* fields
 * @node_nchunks:   total number of chunks allocated to this node
 * @node_nhuge:     total number of huge page based chunks
 * @node_partial:   list of chunks with one or more free slabs
 * @node_full:      list of chunks with no free slabs
 *
 * A node is a cache of NUMA-node affined chunks of memory.
 * In practice, NUMA-node affinity is not guaranteed.
 */
struct kmc_node {
    struct mutex     node_lock     HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct list_head node_partial  HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head node_full;
    uint             node_nchunks;
    uint             node_nhuge;
};

/**
 * struct kmc_chunk - per-numa node affined chunk of memory
 * @ch_magic:   used for sanity checking
 * @ch_hugecnt: number of huge pages used by this chunk
 * @ch_used:    number of slabs in use from this chunk
 * @ch_entry:   list linkage for node_partial/node_full
 * @ch_slabs:   list of free slabs
 * @ch_node:    ptr to node which manages this chunk
 * @ch_base:    base of mmap'd chunk
 * @ch_basesz:  size of mmap'd chunk
 * @ch_slabv:   vector of slab headers
 *
 * A "chunk" of memory is a 2M contiguous piece of virtual memory
 * aligned on a 2M boundary from which slabs are allocated.
 * A chunk is affined to a NUMA node, and its slabs may be allocated
 * and affined only to CPUs local to that node.  Chunks are created
 * fully populated, but over time pages from the chunk could migrate
 * to other nodes.
 */
struct kmc_chunk {
    struct kmc_node  *ch_node;
    struct list_head *ch_list;
    void *            ch_base;
    size_t            ch_basesz;
    void             *ch_magic;

    struct list_head  ch_slabs HSE_ALIGNED(SMP_CACHE_BYTES);
    int               ch_hugecnt;
    int               ch_used;
    struct list_head  ch_entry;

    struct kmc_slab   ch_slabv[KMC_SPC_MAX];
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
    spinlock_t        pcpu_lock     HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct list_head  pcpu_partial  HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head  pcpu_empty;
    struct list_head  pcpu_full;
};

/**
 * struct kmem_cache - a zone of uniformly sized parcels of memory
 * @zone_iasz:          item size aligned to zone_item_align
 * @zone_isize:         caller specified item size
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
    struct kmc_node    *zone_nodev;
    uint                zone_iasz;
    uint                zone_imax;
    uint                zone_isize;
    uint                zone_ialign;
    int                 zone_delay;
    bool                zone_packed;
    void              (*zone_ctor)(void *);
    void               *zone_magic;
    struct list_head    zone_entry;
    ulong               zone_flags;
    int                 zone_packedv[KMC_NODES_MAX];
    struct delayed_work zone_dwork;

    spinlock_t          zone_lock  HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    char                zone_name[24];

    struct list_head    zone_slabs  HSE_ALIGNED(SMP_CACHE_BYTES);
    uint                zone_nslabs;
    ulong               zone_zalloc;
    ulong               zone_zfree;
    ulong               zone_salloc;
    ulong               zone_sfree;

    struct kmc_pcpu     zone_pcpuv[KMC_PCPU_MAX * KMC_NODES_MAX];
};

/**
 * struct kmc - kmem cache globals
 *
 * Zones that leverage huge pages use the upper half per-node objects,
 * zones based on normal pages use the lower half per-node objects.
 */
static struct {
    struct kmem_cache       *kmc_pagecache;
    struct workqueue_struct *kmc_wq;
    atomic_t                 kmc_huge_used;
    uint                     kmc_huge_max;

    struct mutex     kmc_lock  HSE_ALIGNED(SMP_CACHE_BYTES);
    struct list_head kmc_zones;
    int              kmc_nzones;
    struct kmc_node  kmc_nodev[KMC_NODES_MAX * 2];
} kmc;

/* clang-format on */

static void
kmc_reaper(struct work_struct *work);

struct kmc_chunk *
kmc_chunk_create(uint cpuid, bool tryhuge)
{
    int flags = MAP_ANON | MAP_PRIVATE | MAP_HUGETLB | MAP_POPULATE;
    int prot = PROT_READ | PROT_WRITE;
    size_t chunksz, hugesz, basesz;
    struct kmc_chunk *chunk;
    struct kmc_slab * slab;
    cpu_set_t omask, nmask;
    int hugecnt, rc, i;
    void *base, *mem;

    CPU_ZERO(&omask);
    CPU_ZERO(&nmask);
    CPU_SET(cpuid, &nmask);

    rc = pthread_getaffinity_np(pthread_self(), sizeof(omask), &omask);
    if (rc)
        return NULL;

    rc = pthread_setaffinity_np(pthread_self(), sizeof(nmask), &nmask);
    ev(rc); /* oh well, better to keep going... */

    chunksz = KMC_CHUNK_SZ;
    hugesz = 2 * 1024 * 1024;
    basesz = chunksz;
    hugecnt = 0;

    if (tryhuge && IS_ALIGNED(chunksz, hugesz)) {
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
    if (ev(base == MAP_FAILED)) {
        pthread_setaffinity_np(pthread_self(), sizeof(omask), &omask);
        return NULL;
    }

    mem = PTR_ALIGN(base, chunksz);
    basesz = (size_t)(mem - base) + chunksz;

    /* Trim the excess pages from the end of the chunk.
     *
     * [HSE_REVISIT] If base is not chunk aligned then we'll waste the
     * VMA range from base to mem.  Probably we should allocate a very
     * large VMA from which to carve out our 2MB aligned chunks, which
     * would waste only a few pages at the start of the super chunk.
     */
    if (mremap(base, chunksz * 2, basesz, 0) != base) {
        pthread_setaffinity_np(pthread_self(), sizeof(omask), &omask);
        munmap(base, chunksz * 2);
        ev(1);
        return NULL;
    }

    if (ev(mem > base))
        madvise(base, mem - base, MADV_DONTNEED);

    ev(1);

    /* Initialize the chunk header, which is placed at the end
     * of the chunk.
     */
  chunk_init:
    chunk = mem + chunksz - sizeof(*chunk);
    chunk->ch_magic = chunk;
    chunk->ch_hugecnt = hugecnt;
    chunk->ch_base = base;
    chunk->ch_basesz = basesz;
    INIT_LIST_HEAD(&chunk->ch_slabs);

    /* Initialize the zone invariant parts of each slab header.  The
     * slab specific fields will be initialized by kmc_slab_alloc().
     */
    for (i = 0; i < KMC_SPC_MAX; ++i) {
        slab = chunk->ch_slabv + i;
        slab->slab_chunk = chunk;
        slab->slab_base = mem + KMC_SLAB_SZ * i;
        slab->slab_end = slab->slab_base + KMC_SLAB_SZ;
        if (slab->slab_end > (void *)chunk)
            slab->slab_end -= sizeof(*chunk);
        slab->slab_magic = slab;

        assert(slab->slab_base < (void *)chunk);
        assert(slab->slab_end <= (void *)chunk);

        list_add(&slab->slab_entry, &chunk->ch_slabs);
    }

    pthread_setaffinity_np(pthread_self(), sizeof(omask), &omask);

    return chunk;
}

void
kmc_chunk_destroy(struct kmc_chunk *chunk)
{
    int hugecnt, i;

    if (!chunk)
        return;

    assert(chunk->ch_magic == chunk);
    chunk->ch_magic = (void *)0xdeadbeefdeadbeef;
    hugecnt = chunk->ch_hugecnt;

    for (i = 0; i < KMC_SPC_MAX; ++i)
        chunk->ch_slabv[i].slab_magic = (void *)0xdeadbeefdeadbeef;

    munmap(chunk->ch_base, chunk->ch_basesz);

    atomic_sub(hugecnt, &kmc.kmc_huge_used);
}

struct kmc_slab *
kmc_slab_alloc(struct kmem_cache *zone, uint cpuid)
{
    struct kmc_chunk *chunk;
    struct kmc_slab  *slab;
    struct kmc_node  *node;
    char *item;
    size_t sz;
    uint i;

    node = zone->zone_nodev + (hse_cpu2node(cpuid) % KMC_NODES_MAX);

    kmc_node_lock(node);
    chunk = kmc_chunk_first(&node->node_partial);
    if (!chunk) {
        chunk = kmc_chunk_create(cpuid, zone->zone_nodev > kmc.kmc_nodev);
        if (!chunk) {
            kmc_node_unlock(node);
            return NULL;
        }

        chunk->ch_node = node;
        chunk->ch_list = &node->node_partial;
        list_add_tail(&chunk->ch_entry, chunk->ch_list);
        node->node_nhuge += chunk->ch_hugecnt;
        ++node->node_nchunks;

        chunk = kmc_chunk_first(&node->node_partial);
    }

    slab = kmc_slab_first(&chunk->ch_slabs);
    assert(slab);

    list_del(&slab->slab_entry);

    if (++chunk->ch_used >= KMC_SPC_MAX) {
        list_del(&chunk->ch_entry);
        chunk->ch_list = &node->node_full;
        list_add_tail(&chunk->ch_entry, chunk->ch_list);
    }
    kmc_node_unlock(node);

    assert(slab->slab_magic == slab);
    assert(slab->slab_chunk == chunk);
    assert(slab->slab_iused == 0);

    /* We must partially reinitialize the slab because
     * it may have been used by another zone.
     */
    slab->slab_cache0 = NULL;
    slab->slab_cache1 = NULL;
    slab->slab_icur = 0;
    slab->slab_expired = false;
    slab->slab_zalloc = 0;
    slab->slab_zfree = 0;

    /* If the end of the slab overlaps the chunk header then we
     * reduce the number of items such that there's no overlap.
     */
    slab->slab_imax = zone->zone_imax;

    sz = (void *)chunk - slab->slab_base;
    if (sz < KMC_SLAB_SZ)
        slab->slab_imax = sz / zone->zone_iasz;

    if (zone->zone_ctor) {
        for (i = 0; i < slab->slab_imax; ++i) {
            item = (char *)slab->slab_base + zone->zone_iasz * i;
            zone->zone_ctor(item);
        }
    }

    kmc_zone_lock(zone);
    list_add(&slab->slab_zentry, &zone->zone_slabs);
    ++zone->zone_nslabs;
    ++zone->zone_salloc;
    kmc_zone_unlock(zone);

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

    kmc_zone_lock(zone);
    list_del(&slab->slab_zentry);
    zone->zone_zalloc += slab->slab_zalloc;
    zone->zone_zfree += slab->slab_zfree;
    --zone->zone_nslabs;
    ++zone->zone_sfree;
    kmc_zone_unlock(zone);

    chunk = slab->slab_chunk;
    assert(chunk->ch_magic == chunk);

    node = chunk->ch_node;

    kmc_node_lock(node);
    list_add(&slab->slab_entry, &chunk->ch_slabs);

    if (--chunk->ch_used > 0) {
        if (chunk->ch_list != &node->node_partial) {
            list_del(&chunk->ch_entry);
            chunk->ch_list = &node->node_partial;
            list_add_tail(&chunk->ch_entry, chunk->ch_list);
        }
        chunk = NULL;
    } else {
        assert(chunk->ch_used == 0);
        list_del(&chunk->ch_entry);
        chunk->ch_list = NULL;
        --node->node_nchunks;
        node->node_nhuge -= chunk->ch_hugecnt;
    }
    kmc_node_unlock(node);

    if (ev(chunk))
        kmc_chunk_destroy(chunk);
}

void *
kmem_cache_alloc_impl(struct kmem_cache *zone, uint cpuid)
{
    struct kmc_pcpu *pcpu;
    struct kmc_slab *slab;
    uint nodeid, coreid;
    void *mem;

    assert(zone);
    assert(zone->zone_magic == zone);

    nodeid = hse_cpu2node(cpuid);
    coreid = hse_cpu2core(cpuid);

    if (HSE_UNLIKELY(zone->zone_packed)) {
        if (hse_cpu2core(zone->zone_packedv[nodeid]) != coreid) {
            cpuid = zone->zone_packedv[nodeid];
            nodeid = hse_cpu2node(cpuid);
            coreid = hse_cpu2core(cpuid);
        }
    }

    pcpu = zone->zone_pcpuv;
    pcpu += (nodeid % KMC_NODES_MAX) * KMC_PCPU_MAX;
    pcpu += (coreid % KMC_PCPU_MAX);

    kmc_pcpu_lock(pcpu);
    while (1) {
        slab = kmc_slab_first(&pcpu->pcpu_partial);
        if (slab)
            break;

        slab = kmc_slab_first(&pcpu->pcpu_empty);
        if (slab) {
            list_del(&slab->slab_entry);
            slab->slab_list = &pcpu->pcpu_partial;
            list_add(&slab->slab_entry, slab->slab_list);
            break;
        }
        kmc_pcpu_unlock(pcpu);

        slab = kmc_slab_alloc(zone, cpuid);
        if (!slab)
            return NULL;

        kmc_pcpu_lock(pcpu);
        if (slab) {
            slab->slab_list = &pcpu->pcpu_empty;
            list_add(&slab->slab_entry, slab->slab_list);
            slab->slab_expired = false;
            slab->slab_pcpu = pcpu;
        }
    }

    assert(slab->slab_magic == slab);
    assert(slab->slab_iused < slab->slab_imax);
    assert(slab->slab_chunk->ch_magic == slab->slab_chunk);

    if (slab->slab_cache0) {
        mem = slab->slab_cache0;
        slab->slab_cache0 = *(void **)mem;
    } else if (slab->slab_cache1) {
        mem = slab->slab_cache1;
        slab->slab_cache1 = *(void **)mem;
    } else {
        assert(slab->slab_icur < slab->slab_imax);
        mem = slab->slab_base + zone->zone_iasz * slab->slab_icur++;
    }

    if (++slab->slab_iused >= slab->slab_imax) {
        list_del(&slab->slab_entry);
        slab->slab_list = &pcpu->pcpu_full;
        list_add(&slab->slab_entry, slab->slab_list);
    }

    ++slab->slab_zalloc;
    kmc_pcpu_unlock(pcpu);

#ifdef HSE_BUILD_DEBUG
    *(void **)(mem + zone->zone_iasz - sizeof(void *)) = NULL;
#endif

    return mem;
}

void *
kmem_cache_alloc(struct kmem_cache *zone)
{
    return kmem_cache_alloc_impl(zone, raw_smp_processor_id());
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
kmc_addr2slab(struct kmem_cache *zone, void *mem)
{
    struct kmc_chunk *chunk;
    struct kmc_slab * slab;
    uintptr_t         addr;

    assert(zone->zone_magic == zone);

    addr = (uintptr_t)mem;
    if (!addr)
        return NULL;

    /* Verify item alignment.
     */
    if (HSE_UNLIKELY( addr & (zone->zone_ialign - 1) )) {
        assert((addr & (zone->zone_ialign - 1)) == 0);
        abort(); /* invalid free address */
    }

    /* Find the base address of the chunk from the upper bits of the given
     * addr (chunks are always power-of-2 aligned).  If chunk is invalid
     * we might just crash trying to read ch_magic.
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

    /* Verify item is within the slab (last slab in a chunk
     * is shorter than the rest).
     */
    if (HSE_UNLIKELY( mem + zone->zone_iasz > slab->slab_end )) {
        assert(mem + zone->zone_iasz <= slab->slab_end);
        abort(); /* invalid free or slab corruption */
    }

#ifdef HSE_BUILD_DEBUG
    /* Check to see if this item is in the slab's item cache.  It's unlikely
     * but possible that the user will have stored these same sentinel values
     * into the item, in which case this check will misfire.
     */
    if (*(void **)(mem + zone->zone_iasz - sizeof(void *)) == slab) {
        assert(*((void **)mem + zone->zone_iasz - sizeof(void *)) != slab);
        abort(); /* possible double free or slab corruption */
    }
#endif

    return slab;
}

void
kmem_cache_free(struct kmem_cache *zone, void *mem)
{
    struct kmc_slab *slab;
    struct kmc_pcpu *pcpu;
    void **cachep;

    assert(zone);
    assert(zone->zone_magic == zone);

    slab = kmc_addr2slab(zone, mem);
    if (!slab)
        return;

    assert(slab->slab_magic == slab);

#ifdef HSE_BUILD_DEBUG
    *(void **)(mem + zone->zone_iasz - sizeof(void *)) = slab;
#endif

    pcpu = slab->slab_pcpu;

    if (mem - slab->slab_base < KMC_SLAB_SZ / 2)
        cachep = &slab->slab_cache0;
    else
        cachep = &slab->slab_cache1;

    kmc_pcpu_lock(pcpu);
    *(void **)mem = *cachep;
    *cachep = mem;

    if (--slab->slab_iused > 0) {
        if (slab->slab_list != &pcpu->pcpu_partial) {
            list_del(&slab->slab_entry);
            slab->slab_list = &pcpu->pcpu_partial;
            list_add_tail(&slab->slab_entry, slab->slab_list);
        }
    } else {
        if (slab != kmc_slab_first(&pcpu->pcpu_partial)) {
            list_del(&slab->slab_entry);
            slab->slab_list = &pcpu->pcpu_empty;
            list_add(&slab->slab_entry, slab->slab_list);
            slab->slab_expired = false;
        }
    }

    ++slab->slab_zfree;
    kmc_pcpu_unlock(pcpu);
}

static void
kmc_reaper(struct work_struct *work)
{
    struct kmem_cache *zone;
    struct kmc_slab *slab, *next;
    ulong delay;
    int i;

    zone = container_of(work, struct kmem_cache, zone_dwork.work);
    assert(zone->zone_magic == zone);

    /* Examine each per-cpu cache and free all slabs that
     * haven't been used since the last time we checked.
     */
    for (i = 0; i < NELEM(zone->zone_pcpuv); ++i) {
        struct kmc_pcpu *pcpu = zone->zone_pcpuv + i;
        struct list_head expired;

        INIT_LIST_HEAD(&expired);

        kmc_pcpu_lock(pcpu);
        slab = kmc_slab_first(&pcpu->pcpu_partial);
        if (slab && slab->slab_iused == 0) {
            list_del(&slab->slab_entry);
            slab->slab_list = &pcpu->pcpu_empty;
            list_add(&slab->slab_entry, slab->slab_list);
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

        kmc_slab_foreach(slab, next, &expired)
            kmc_slab_free(zone, slab);
    }

    delay = msecs_to_jiffies(zone->zone_delay + (get_cycles() % 1024) * 4);
    queue_delayed_work(kmc.kmc_wq, &zone->zone_dwork, delay);
}

struct kmem_cache *
kmem_cache_create(const char *name, size_t size, size_t align, ulong flags, void (*ctor)(void *))
{
    struct kmem_cache *zone;
    size_t slab_sz, iasz;
    ulong delay;
    uint i;

    assert(kmc.kmc_wq);

    if (ev(!name || (align & (align - 1))))
        return NULL;

    /* [HSE_REVISIT] Disable constructors until we can figure out
     * how to avoid calling them unnecessarily.
     */
    if (ctor)
        return NULL;

    align = max_t(size_t, align, _Alignof(max_align_t));

    if (flags & SLAB_HWCACHE_ALIGN)
        align = ALIGN(align, SMP_CACHE_BYTES);

    iasz = max_t(uint, align, ALIGN(size, align)); /* in case size == 0 */

    slab_sz = KMC_SLAB_SZ;
    if (iasz > slab_sz / 2)
        return NULL;

    zone = alloc_aligned(sizeof(*zone), alignof(*zone));
    if (ev(!zone))
        return NULL;

    memset(zone, 0, sizeof(*zone));
    zone->zone_iasz = iasz;
    zone->zone_imax = KMC_SLAB_SZ / iasz;
    zone->zone_isize = size;
    zone->zone_ialign = align;
    zone->zone_packed = !!(flags & SLAB_PACKED);
    zone->zone_flags = flags;
    zone->zone_ctor = ctor;
    INIT_LIST_HEAD(&zone->zone_slabs);
    zone->zone_delay = 15000;
    zone->zone_magic = zone;

    if (zone->zone_packed) {
        uint cpumax, cpuid, j;
        cpu_set_t omask;

        pthread_getaffinity_np(pthread_self(), sizeof(omask), &omask);
        CPU_CLR(0, &omask); /* stay clear of cpu 0 */

        cpumax = get_nprocs_conf();
        cpuid = get_cycles();

        for (i = 0; i < NELEM(zone->zone_packedv); ++i) {
            for (j = 0; j < cpumax; ++j) {
                cpuid = (cpuid + 7) % cpumax;

                if (CPU_ISSET(cpuid, &omask) && hse_cpu2node(cpuid) == i) {
                    zone->zone_packedv[i] = cpuid;
                    break;
                }
            }
        }
    }

    kmc_zone_lock_init(zone);
    strlcpy(zone->zone_name, name, sizeof(zone->zone_name));

    /* Huge-page based zones use the upper half nodes.
     */
    zone->zone_nodev = kmc.kmc_nodev;
    if (iasz > (PAGE_SIZE / 4) || (flags & SLAB_HUGE)) {
        zone->zone_nodev += KMC_NODES_MAX;
        zone->zone_flags |= SLAB_HUGE;
    }

    for (i = 0; i < NELEM(zone->zone_pcpuv); ++i) {
        struct kmc_pcpu *pcpu = zone->zone_pcpuv + i;

        kmc_pcpu_lock_init(pcpu);
        INIT_LIST_HEAD(&pcpu->pcpu_partial);
        INIT_LIST_HEAD(&pcpu->pcpu_full);
        INIT_LIST_HEAD(&pcpu->pcpu_empty);
    }

    mutex_lock(&kmc.kmc_lock);
    list_add_tail(&zone->zone_entry, &kmc.kmc_zones);
    ++kmc.kmc_nzones;
    mutex_unlock(&kmc.kmc_lock);

    INIT_DELAYED_WORK(&zone->zone_dwork, kmc_reaper);
    delay = msecs_to_jiffies(zone->zone_delay);
    queue_delayed_work(kmc.kmc_wq, &zone->zone_dwork, delay);

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

    mutex_lock(&kmc.kmc_lock);
    list_del(&zone->zone_entry);
    --kmc.kmc_nzones;
    mutex_unlock(&kmc.kmc_lock);

    while (!cancel_delayed_work(&zone->zone_dwork))
        usleep(1000);

    for (i = 0; i < NELEM(zone->zone_pcpuv); ++i) {
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
    mutex_init(&kmc.kmc_lock);
    INIT_LIST_HEAD(&kmc.kmc_zones);
    kmc.kmc_nzones = 0;
    kmc.kmc_huge_max = KMC_HUGE_MAX;

    for (i = 0; i < NELEM(kmc.kmc_nodev); ++i) {
        kmc_node_lock_init(kmc.kmc_nodev + i);
        kmc.kmc_nodev[i].node_nchunks = 0;
        kmc.kmc_nodev[i].node_nhuge = 0;
        INIT_LIST_HEAD(&kmc.kmc_nodev[i].node_partial);
        INIT_LIST_HEAD(&kmc.kmc_nodev[i].node_full);
    }

    kmc.kmc_wq = alloc_workqueue("kmc", 0, 1);
    if (ev(!kmc.kmc_wq)) {
        for (i = 0; i < NELEM(kmc.kmc_nodev); ++i)
            kmc_node_lock_destroy(kmc.kmc_nodev + i);
        mutex_destroy(&kmc.kmc_lock);
        return merr(ENOMEM);
    }

    kmc.kmc_pagecache = kmem_cache_create("kvdb_pagecache", PAGE_SIZE, PAGE_SIZE, 0, NULL);

    if (ev(!kmc.kmc_pagecache)) {
        destroy_workqueue(kmc.kmc_wq);
        for (i = 0; i < NELEM(kmc.kmc_nodev); ++i)
            kmc_node_lock_destroy(kmc.kmc_nodev + i);
        mutex_destroy(&kmc.kmc_lock);
        return merr(ENOMEM);
    }

    return 0;
}

void
kmem_cache_fini(void)
{
    struct kmem_cache *zone, *next;
    int i;

    if (!kmc.kmc_pagecache)
        return;

    kmc.kmc_pagecache = NULL;

    kmc_zone_foreach(zone, next, &kmc.kmc_zones)
        kmem_cache_destroy((void *)zone);

    destroy_workqueue(kmc.kmc_wq);

    for (i = 0; i < NELEM(kmc.kmc_nodev); ++i)
        kmc_node_lock_destroy(kmc.kmc_nodev + i);

    mutex_destroy(&kmc.kmc_lock);
}

static u64
kmc_test(int which, size_t size, size_t align, void *zone, uint *alignedp)
{
    u64 itermax, naligned, tstart;
    uint addrmod, addrc, i;
    void **addrv;

    itermax = clamp_t(u64, (1ul << 30) / size, 8192, 1ul << 20);
    naligned = 0;

    addrc = (itermax / 4);
    addrv = malloc(sizeof(*addrv) * addrc);
    if (!addrv)
        return 0;

    memset(addrv, 0, sizeof(*addrv) * addrc);

    addrmod = (1u << ilog2(addrc)) - 1;

    if (size > (KMC_SLAB_SZ / 2) && addrmod > 63) {
        addrmod = 63;
    }

    tstart = get_time_ns();

    for (i = 0; i < itermax; ++i) {
        int idx = i & addrmod;

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

        case 5:
            vlb_free(addrv[idx], sizeof(void *));
            addrv[idx] = vlb_alloc(size);
            break;

        case 6:
            vlb_free(addrv[idx], size);
            addrv[idx] = vlb_alloc(size);
            break;

        default:
            break;
        }

        if (((uintptr_t)addrv[idx] & (align - 1)) == 0)
            ++naligned;

        *(uintptr_t *)addrv[idx] = i;
    }

    for (i = 0; i < addrc; ++i) {
        switch (which) {
        case 3:
            free_aligned(addrv[i]);
            break;

        case 4:
            kmem_cache_free(zone, addrv[i]);
            break;

        case 5:
            vlb_free(addrv[i], sizeof(void *));
            break;

        case 6:
            vlb_free(addrv[i], size);
            break;

        default:
            free(addrv[i]);
            break;
        }
    }

    tstart = (get_time_ns() - tstart) / itermax;

    *alignedp = naligned * 100 / itermax;
    free(addrv);

    return tstart;
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
    size_t       hsz, sz;
    int          rc, n;

    n = snprintf(buf, sizeof(buf), "%4s %5s %10s %14s %14s %17s %9s\n",
                 "cpu", "size", "malloc", "aligned_alloc",
                 "alloc_aligned", "kmem_cache_alloc", "vlb_alloc");
    rest_write_safe(info->resp_fd, buf, n);

    for (sz = 8; sz < 16ul << 20; sz *= 2) {
        const char *suffix = "bkmg";
        cpu_set_t omask, nmask;
        size_t align = sz;
        uint naligned = 0;
        void *zone;
        u64 nspa;

        hsz = sz;
        while (hsz / 1024 > 0) {
            hsz /= 1024;
            ++suffix;
        }

        CPU_ZERO(&omask);
        CPU_ZERO(&nmask);
        CPU_SET(raw_smp_processor_id(), &nmask);

        rc = pthread_getaffinity_np(pthread_self(), sizeof(omask), &omask);
        if (rc)
            continue;

        rc = pthread_setaffinity_np(pthread_self(), sizeof(nmask), &nmask);
        if (rc)
            continue;

        zone = kmem_cache_create(__func__, sz, align, 0, NULL);

        n = snprintf(buf, bufsz, "%4u %4zu%c", raw_smp_processor_id(), hsz, *suffix);
        rest_write_safe(info->resp_fd, buf, n);

        nspa = kmc_test(1, sz, align, NULL, &naligned);
        nspa = kmc_test(1, sz, align, NULL, &naligned);
        n = snprintf(buf, bufsz, " %6zu,%-3u",  nspa, naligned);
        rest_write_safe(info->resp_fd, buf, n);

        nspa = kmc_test(2, sz, align, NULL, &naligned);
        nspa = kmc_test(2, sz, align, NULL, &naligned);
        n = snprintf(buf, bufsz, " %10zu,%-3u",  nspa, naligned);
        rest_write_safe(info->resp_fd, buf, n);

        nspa = kmc_test(3, sz, align, NULL, &naligned);
        nspa = kmc_test(3, sz, align, NULL, &naligned);
        n = snprintf(buf, bufsz, " %10zu,%-3u",  nspa, naligned);
        rest_write_safe(info->resp_fd, buf, n);

        if (zone) {
            nspa = kmc_test(4, sz, align, zone, &naligned);
            nspa = kmc_test(4, sz, align, zone, &naligned);
            n = snprintf(buf, bufsz, " %13zu,%3u %9s",  nspa, naligned, "-");
            rest_write_safe(info->resp_fd, buf, n);
            kmem_cache_destroy(zone);
        } else if (sz > VLB_ALLOCSZ_MAX) {
            nspa = kmc_test(6, sz, align, NULL, &naligned);
            nspa = kmc_test(6, sz, align, NULL, &naligned);
            n = snprintf(buf, bufsz, " %17s %7zu,%u,vma",  "-", nspa, naligned);
            rest_write_safe(info->resp_fd, buf, n);
        } else {
            nspa = kmc_test(5, sz, align, NULL, &naligned);
            nspa = kmc_test(5, sz, align, NULL, &naligned);
            n = snprintf(buf, bufsz, " %17s %7zu,%u",  "-", nspa, naligned);
            rest_write_safe(info->resp_fd, buf, n);
        }

        rest_write_safe(info->resp_fd, "\n", 1);

        pthread_setaffinity_np(pthread_self(), sizeof(omask), &omask);

        usleep(33 * 1000);
    }
}

static int
kmc_addrv_cmp(const void *lhs, const void *rhs)
{
    const void * const *l = lhs;
    const void * const *r = rhs;

    if (*l != *r)
        return (*l < *r) ? -1 : 1;

    return 0;
}

static int
kmc_snprintf(struct kmem_cache *zone, char *buf, size_t bufsz, const char *fmt)
{
    ulong nempty, nchunks, nhuge;
    int addrmax, addrc, cc, i;
    struct list_head *head;
    struct kmc_slab *slab;
    ulong zalloc, zfree;
    ulong salloc, sfree;
    ulong iused, itotal;
    char flagsbuf[128];
    void **addrv;

    addrmax = 1024;
    addrv = malloc(sizeof(*addrv) * addrmax);
    if (addrv) {
        addrv[0] = NULL;
        addrc = 1;
    }

    nempty = nchunks = nhuge = 0;
    salloc = sfree = 0;
    iused = itotal = 0;

    kmc_zone_lock(zone);
    head = &zone->zone_slabs;
    zalloc = zone->zone_zalloc;
    zfree = zone->zone_zfree;

    slab = list_first_entry_or_null(head, struct kmc_slab, slab_zentry);
    while (slab) {
        zalloc += slab->slab_zalloc;
        zfree += slab->slab_zfree;
        itotal += slab->slab_imax;
        iused += slab->slab_iused;
        if (slab->slab_iused == 0)
            ++nempty;

        salloc += slab->slab_zalloc;
        sfree += slab->slab_zfree;

        if (addrv && addrc < addrmax) {
            if (addrv[addrc - 1] != slab->slab_chunk)
                addrv[addrc++] = slab->slab_chunk;
        }

        slab = list_next_entry_or_null(slab, slab_zentry, head);
    }
    kmc_zone_unlock(zone);

    if (addrv) {
        qsort(addrv, addrc, sizeof(*addrv), kmc_addrv_cmp);

        /* Determine the number of unique chunks used by this zone.
         */
        for (i = 1; i < addrc; ++i) {
            if (addrv[i] != addrv[i - 1]) {
                struct kmc_chunk *chunk = addrv[i];

                nhuge += chunk->ch_hugecnt;
                ++nchunks;
            }
        }
    }

    snprintf(flagsbuf, sizeof(flagsbuf), "%s%s%s",
             (zone->zone_flags & SLAB_HUGE) ? " huge" : "",
             (zone->zone_flags & SLAB_PACKED) ? " packed" : "",
             (zone->zone_flags & SLAB_HWCACHE_ALIGN) ? " hwalign" : "");

    cc = snprintf(
        buf, bufsz, fmt,
        zone->zone_name,
        nchunks,
        nhuge,
        zone->zone_nslabs,
        (KMC_SLAB_SZ * zone->zone_nslabs) / 1024,
        nempty,
        zone->zone_salloc,
        zone->zone_sfree,
        zone->zone_isize,
        zone->zone_ialign,
        zone->zone_iasz,
        itotal,
        iused,
        zalloc,
        zfree,
        flagsbuf);

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
    uint nchunksv[KMC_NODES_MAX * 2], nchunks;
    uint nfragsv[KMC_NODES_MAX * 2], nfrags;
    uint nhugev[KMC_NODES_MAX * 2], nhuge;
    struct kmem_cache *zone, *next;
    const char *fmt;
    char buf[256];
    int n, i;

    snprintf(
        buf, sizeof(buf),
        "%-20s %6s %4s %5s %7s %6s %6s %6s"
        " %6s %7s %6s %8s %8s %13s %13s %s\n",
        "NAME",
        "CHUNKS",
        "HUGE",
        "SLABS",
        "SLABKB",
        "SEMPTY",
        "SALLOC",
        "SFREE",
        "ISIZE",
        "IALIGN",
        "IASIZE",
        "ITOTAL",
        "IUSED",
        "IALLOC",
        "IFREE",
        "FLAGS...");

    rest_write_safe(info->resp_fd, buf, strlen(buf));

    fmt = "%-20.20s %6lu %4lu %5u %7u %6lu %6lu %6lu"
        " %6u %7u %6u %8lu %8lu %13lu %13lu %s\n";

    mutex_lock(&kmc.kmc_lock);
    kmc_zone_foreach(zone, next, &kmc.kmc_zones) {
        n = kmc_snprintf(zone, buf, sizeof(buf), fmt);
        if (n > 0) {
            n = min_t(int, n, sizeof(buf));
            rest_write_safe(info->resp_fd, buf, n);
        }
    }
    mutex_unlock(&kmc.kmc_lock);

    nchunks = nhuge = nfrags = 0;

    for (i = 0; i < NELEM(kmc.kmc_nodev); ++i) {
        struct kmc_node *node = kmc.kmc_nodev + i;
        struct kmc_chunk *chunk, *next;

        kmc_node_lock(node);
        nfragsv[i] = 0;

        kmc_chunk_foreach(chunk, next, &node->node_partial)
            nfragsv[i] += (chunk->ch_basesz - KMC_CHUNK_SZ) / PAGE_SIZE;

        kmc_chunk_foreach(chunk, next, &node->node_full)
            nfragsv[i] += (chunk->ch_basesz - KMC_CHUNK_SZ) / PAGE_SIZE;

        nfrags += nfragsv[i];

        nchunksv[i] = node->node_nchunks;
        nchunks += nchunksv[i];

        nhugev[i] = node->node_nhuge;
        nhuge += nhugev[i];
        kmc_node_unlock(node);
    }

    n = snprintf(buf, sizeof(buf), "SUMMARY: chunks: %u total, %u huge, %u vma frag",
                 nchunks, nhuge, nfrags);

    for (i = 0; i < KMC_NODES_MAX; ++i) {
        n += snprintf(buf + n, sizeof(buf) - n, ", node %u: %u %u %u",
                      i, nchunksv[i] + nchunksv[i + KMC_NODES_MAX],
                      nhugev[i] + nhugev[i + KMC_NODES_MAX],
                      nfragsv[i] + nfragsv[i + KMC_NODES_MAX]);
    }

    strcat(buf + n, "\n");

    rest_write_safe(info->resp_fd, buf, n + 1);

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
