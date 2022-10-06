/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
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

#include <sys/mman.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>
#include <cjson/cJSON_Utils.h>

#include <hse/logging/logging.h>
#include <hse/rest/headers.h>
#include <hse/rest/method.h>
#include <hse/rest/params.h>
#include <hse/rest/request.h>
#include <hse/rest/response.h>
#include <hse/rest/status.h>
#include <hse_util/alloc.h>
#include <hse_util/assert.h>
#include <hse_util/atomic.h>
#include <hse_util/event_counter.h>
#include <hse_util/log2.h>
#include <hse_util/minmax.h>
#include <hse_util/mutex.h>
#include <hse_util/page.h>
#include <hse_util/slab.h>
#include <hse_util/spinlock.h>
#include <hse_util/storage.h>
#include <hse_util/platform.h>
#include <hse_util/vlb.h>
#include <hse_util/workqueue.h>

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
 * @slab_descidx:   index into zone_descv[] for this slab
 * @slab_magic:     used to detect access to invalid slab
 *
 * A slab is a 256KB contiguous piece of virtual memory aligned on a 256KB
 * boundary from which some number of items may be allocated.  Slabs are
 * affined to a per-cpu bucket when they are allocated, and remain affined
 * until the last item is freed.
 */
struct kmc_slab {
    struct list_head  slab_entry HSE_ACP_ALIGNED;
    struct list_head  slab_zentry;
    struct kmc_chunk *slab_chunk;
    struct kmc_pcpu  *slab_pcpu;
    void             *slab_base;
    void             *slab_end;

    void             *slab_cache0 HSE_L1D_ALIGNED;
    void             *slab_cache1;
    uint              slab_icur;
    uint              slab_iused;
    uint              slab_imax;
    bool              slab_expired;
    struct list_head *slab_list;
    ulong             slab_zalloc;
    ulong             slab_zfree;
    uint32_t          slab_descidx;
    uint32_t          slab_magic;
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
    struct mutex     node_lock     HSE_ACP_ALIGNED;
    struct list_head node_partial  HSE_L1X_ALIGNED;
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

    struct list_head  ch_slabs HSE_L1D_ALIGNED;
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
    spinlock_t        pcpu_lock    HSE_ACP_ALIGNED;
    struct list_head  pcpu_partial HSE_L1X_ALIGNED;
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
 * @zone_slabs;         list of slabs in use by this cache
 * @zone_nslabs;        number of slabs in use by this cache
 * @zone_descmax;       max slots in zone_descv[]
 * @zone_descidx;       current slot in zone_descv[] from which to allocate
 * @zone_zalloc;        total calls to kmem_cache_alloc on this zone
 * @zone_zfree;         total calls to kmem_cache_free on this zone
 * @zone_salloc;        total slab allocations on this zone
 * @zone_sfree;         total slab free on this zone
 * @zone_name;          kmem cache name
 * @zone_node;          vector of per-numa nodes objects
 * @zone_entry;         linkage on global cache list
 * @zone_dwork;         dwork for periodic zone reaping
 * @zone_pcpuv;         per-cpu slab management
 * @zone_descv;         slab descriptor map
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
    struct delayed_work zone_dwork;

    spinlock_t          zone_lock HSE_ACP_ALIGNED;
    char                zone_name[24];

    struct list_head    zone_slabs HSE_L1D_ALIGNED;
    uint                zone_nslabs;
    uint                zone_descmax;
    uint                zone_descidx;
    ulong               zone_zalloc;
    ulong               zone_zfree;
    ulong               zone_salloc;
    ulong               zone_sfree;

    struct kmc_pcpu     zone_pcpuv[KMC_PCPU_MAX * KMC_NODES_MAX];

    struct kmc_slab    *zone_descv[];
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
    atomic_int               kmc_huge_used;
    uint                     kmc_huge_max;

    struct mutex     kmc_lock HSE_L1D_ALIGNED;
    struct list_head kmc_zones;
    int              kmc_nzones;
    struct kmc_node  kmc_nodev[KMC_NODES_MAX * 2];
} kmc;

/* clang-format on */

static void
kmc_reaper(struct work_struct *work);

static HSE_ALWAYS_INLINE void
assert_slab_magic(struct kmc_slab *slab)
{
    assert(slab->slab_magic == (uint32_t)(uintptr_t)slab);
}


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
        if (atomic_fetch_add(&kmc.kmc_huge_used, hugecnt) > kmc.kmc_huge_max - hugecnt) {
            atomic_fetch_sub(&kmc.kmc_huge_used, hugecnt);
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

        atomic_sub(&kmc.kmc_huge_used, hugecnt);
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

    if (ev_info(mem > base))
        madvise(base, mem - base, MADV_DONTNEED);

    ev_info(1);

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
        slab->slab_magic = (uintptr_t)slab;

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
        chunk->ch_slabv[i].slab_magic = 0xdeadbeef;

    munmap(chunk->ch_base, chunk->ch_basesz);

    atomic_sub(&kmc.kmc_huge_used, hugecnt);
}

struct kmc_slab *
kmc_slab_alloc(struct kmem_cache *zone, uint cpuid, uint nodeid)
{
    struct kmc_chunk *chunk;
    struct kmc_slab  *slab;
    struct kmc_node  *node;
    char *item;
    size_t sz;
    uint i;

    node = zone->zone_nodev + (nodeid % KMC_NODES_MAX);

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

    list_del(&slab->slab_entry);

    if (++chunk->ch_used >= KMC_SPC_MAX) {
        list_del(&chunk->ch_entry);
        chunk->ch_list = &node->node_full;
        list_add_tail(&chunk->ch_entry, chunk->ch_list);
    }
    kmc_node_unlock(node);

    assert_slab_magic(slab);
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

    /* Find an empty slot in the zone's descriptor cache if this zone
     * was created with the SLAB_DESC flag.
     */
    for (i = 0; i < zone->zone_descmax; ++i) {
        if (!zone->zone_descv[zone->zone_descidx])
            break;

        zone->zone_descidx = (zone->zone_descidx + 1) % zone->zone_descmax;
    }

    slab->slab_descidx = UINT32_MAX;

    if (i < zone->zone_descmax) {
        slab->slab_descidx = zone->zone_descidx;
        zone->zone_descv[zone->zone_descidx] = slab;
    }
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

    assert_slab_magic(slab);

    if (slab->slab_iused > 0) {
        log_err("mem leak in zone %s, slab %p, iused %u, max %u",
                zone->zone_name, slab,
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

    if (slab->slab_descidx < zone->zone_descmax) {
        assert(zone->zone_descv[slab->slab_descidx] == slab);

        zone->zone_descv[slab->slab_descidx] = NULL;
    }
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

    if (ev_info(chunk))
        kmc_chunk_destroy(chunk);
}

void *
kmem_cache_alloc_impl(struct kmem_cache *zone, uint cpuid, uint nodeid)
{
    struct kmc_pcpu *pcpu;
    struct kmc_slab *slab;
    void *mem;

    assert(zone && zone->zone_magic == zone);

    pcpu = zone->zone_pcpuv;
    pcpu += (nodeid % KMC_NODES_MAX) * KMC_PCPU_MAX;

    if (!zone->zone_packed)
        pcpu += (cpuid % KMC_PCPU_MAX);

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

        slab = kmc_slab_alloc(zone, cpuid, nodeid);
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

    assert_slab_magic(slab);
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
    uint cpu, node;

    cpu = hse_getcpu(&node);

    return kmem_cache_alloc_impl(zone, cpu, node);
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

    if (HSE_UNLIKELY((uint32_t)(uintptr_t)slab != slab->slab_magic)) {
        assert_slab_magic(slab);
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
    if (*(void **)(mem + zone->zone_iasz - sizeof(void *)) == slab)
        abort(); /* possible double free or slab corruption */
#endif

    return slab;
}

void
kmem_cache_free(struct kmem_cache *zone, void *mem)
{
    struct kmc_slab *slab;
    struct kmc_pcpu *pcpu;
    void **cachep;

    assert(zone && zone->zone_magic == zone);

    slab = kmc_addr2slab(zone, mem);
    if (!slab)
        return;

    assert_slab_magic(slab);

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

void *
kmem_cache_desc2addr(struct kmem_cache *zone, uint32_t desc)
{
    struct kmc_slab *slab;
    uint item = (desc << 20) >> 20;
    uint idx = desc >> 12;

    if (idx >= zone->zone_descmax)
        return NULL;

    slab = zone->zone_descv[idx];
    if (!slab)
        return NULL;

    return slab->slab_base + zone->zone_iasz * item;
}

uint32_t
kmem_cache_addr2desc(struct kmem_cache *zone, void *mem)
{
    struct kmc_slab *slab;
    uint32_t item;

    slab = kmc_addr2slab(zone, mem);

    if (!slab || slab->slab_descidx >= zone->zone_descmax)
        return UINT32_MAX;

    item = (mem - slab->slab_base) / zone->zone_iasz;
    assert(item < (1u << 12));

    return (slab->slab_descidx << 12) | item;
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
    uint descmax, i;

    assert(kmc.kmc_wq);

    if (ev(!name || (align & (align - 1))))
        return NULL;

    /* [HSE_REVISIT] Disable constructors until we can figure out
     * how to avoid calling them unnecessarily.
     */
    if (ctor)
        return NULL;

    align = max_t(size_t, align, alignof(max_align_t));

    if (flags & SLAB_HWCACHE_ALIGN)
        align = ALIGN(align, HSE_L1D_LINESIZE);

    iasz = max_t(uint, align, ALIGN(size, align)); /* in case size == 0 */

    /* If the descriptor cache is enabled then the aligned item size
     * must be large enough to prevent more than 2^12 items per slab.
     * We adjust the size of the descriptor map such that the entire
     * allocation is as close to 8M as possible without going over.
     */
    descmax = 0;

    if (flags & SLAB_DESC) {
        if (KMC_SLAB_SZ / iasz > (1u << 12))
            iasz = ALIGN(KMC_SLAB_SZ / (1u << 12), align);

        descmax = (1024 * 1024 * sizeof(void *) - sizeof(*zone)) / sizeof(void *);
    }

    slab_sz = KMC_SLAB_SZ;
    if (iasz > slab_sz / 2)
        return NULL;

    zone = aligned_alloc(__alignof__(*zone), sizeof(*zone) + descmax * 8);
    if (ev(!zone))
        return NULL;

    memset(zone, 0, sizeof(*zone) + descmax * 8);
    zone->zone_iasz = iasz;
    zone->zone_imax = KMC_SLAB_SZ / iasz;
    zone->zone_isize = size;
    zone->zone_ialign = align;
    zone->zone_packed = !!(flags & SLAB_PACKED);
    zone->zone_flags = flags;
    zone->zone_ctor = ctor;
    INIT_LIST_HEAD(&zone->zone_slabs);
    zone->zone_descmax = descmax;
    zone->zone_delay = 15000;
    zone->zone_magic = zone;

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
    free(zone);
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

    kmc.kmc_wq = alloc_workqueue("hse_kmc_reaper", 0, 1, 1);
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

static int
kmc_addrv_cmp(const void *lhs, const void *rhs)
{
    const void * const *l = lhs;
    const void * const *r = rhs;

    if (*l != *r)
        return (*l < *r) ? -1 : 1;

    return 0;
}

enum rest_status
rest_kmc_get_vmstat(const struct rest_request *req, struct rest_response *resp, void *arg)
{
    char *data;
    merr_t err;
    cJSON *root;
    bool pretty;
    struct kmc_slab *slab;
    struct kmem_cache *zone, *next;
    enum rest_status status = REST_STATUS_OK;

    err = rest_params_get(req->rr_params, "pretty", &pretty, false);
    if (ev(err))
        return REST_STATUS_BAD_REQUEST;

    root = cJSON_CreateArray();
    if (ev(!root))
        return REST_STATUS_INTERNAL_SERVER_ERROR;

    mutex_lock(&kmc.kmc_lock);

    kmc_zone_foreach(zone, next, &kmc.kmc_zones) {
        bool bad;
        size_t addrc = 0;
        cJSON *elem = NULL;
        void **addrv = NULL;
        unsigned long iused, itotal;
        unsigned long zalloc, zfree;
        ulong nempty, nchunks, nhuge;
        const unsigned addr_max = 1024;

        elem = cJSON_CreateObject();
        if (ev(!elem)) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            break;
        }

        /* [HSE_TODO]: Greg, is getting a NULL value here fine? */
        addrv = malloc(sizeof(*addrv) * addr_max);
        if (addrv) {
            addrv[0] = NULL;
            addrc = 1;
        }

        kmc_zone_lock(zone);

        zalloc = zone->zone_zalloc;
        zfree = zone->zone_zfree;
        itotal = 0;
        iused = 0;
        nempty = 0;
        nchunks = 0;
        nhuge = 0;

        list_for_each_entry(slab, &zone->zone_slabs, slab_zentry) {
            zalloc += slab->slab_zalloc;
            zfree += slab->slab_zfree;
            itotal += slab->slab_imax;
            iused += slab->slab_iused;
            if (slab->slab_iused == 0)
                nempty++;

            if (addrv && addrc < addr_max) {
                if (addrv[addrc - 1] != slab->slab_chunk)
                    addrv[addrc++] = slab->slab_chunk;
            }
        }

        if (addrv) {
            qsort(addrv, addrc, sizeof(*addrv), kmc_addrv_cmp);

            /* Determine the number of unique chunks used by this zone.
            */
            for (size_t i = 1; i < addrc; i++) {
                if (addrv[i] != addrv[i - 1]) {
                    struct kmc_chunk *chunk = addrv[i];

                    nhuge += chunk->ch_hugecnt;
                    nchunks++;
                }
            }
        }

        free(addrv);

        if (ev(!cJSON_AddItemToArray(root, elem))) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            goto out;
        }

        bad = !cJSON_AddStringToObject(elem, "name", zone->zone_name);
        bad |= !cJSON_AddNumberToObject(elem, "used_chunks", nchunks);
        bad |= !cJSON_AddNumberToObject(elem, "huge_pages", nhuge);
        bad |= !cJSON_AddNumberToObject(elem, "used_slabs", zone->zone_nslabs);
        bad |= !cJSON_AddNumberToObject(elem, "used_slabs_size_kb",
                (KMC_SLAB_SZ * zone->zone_nslabs) >> KB_SHIFT);
        bad |= !cJSON_AddNumberToObject(elem, "empty_slabs", nempty);
        bad |= !cJSON_AddNumberToObject(elem, "allocated_slabs", zone->zone_salloc);
        bad |= !cJSON_AddNumberToObject(elem, "free_slabs", zone->zone_sfree);
        bad |= !cJSON_AddNumberToObject(elem, "item_size", zone->zone_isize);
        bad |= !cJSON_AddNumberToObject(elem, "item_alignment", zone->zone_ialign);
        bad |= !cJSON_AddNumberToObject(elem, "item_aligned_size", zone->zone_iasz);
        bad |= !cJSON_AddNumberToObject(elem, "total_items", itotal);
        bad |= !cJSON_AddNumberToObject(elem, "used_items", iused);
        bad |= !cJSON_AddNumberToObject(elem, "allocations", zalloc);
        bad |= !cJSON_AddNumberToObject(elem, "deallocations", zfree);
        bad |= !cJSON_AddBoolToObject(elem, "huge", zone->zone_flags & SLAB_HUGE);
        bad |= !cJSON_AddBoolToObject(elem, "packed", zone->zone_flags & SLAB_PACKED);
        bad |= !cJSON_AddBoolToObject(elem, "hardware_cache_aligned",
            zone->zone_flags & SLAB_HWCACHE_ALIGN);
        bad |= !cJSON_AddBoolToObject(elem, "descriptor_convertible", zone->zone_flags & SLAB_DESC);

        kmc_zone_unlock(zone);

        if (ev(bad)) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            break;
        }
    }

    mutex_unlock(&kmc.kmc_lock);

    if (status == REST_STATUS_OK) {
        data = (pretty ? cJSON_Print : cJSON_PrintUnformatted)(root);
        if (ev(!data)) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            goto out;
        }

        fputs(data, resp->rr_stream);
        cJSON_free(data);

        err = rest_headers_set(resp->rr_headers, REST_HEADER_CONTENT_TYPE, REST_APPLICATION_JSON);
        if (ev(err)) {
            status = REST_STATUS_INTERNAL_SERVER_ERROR;
            goto out;
        }
    }

out:
    cJSON_Delete(root);

    return status;
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
