/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/spinlock.h>
#include <hse_util/assert.h>
#include <hse_util/timing.h>
#include <hse_util/log2.h>
#include <hse_util/page.h>
#include <hse_util/barrier.h>
#include <hse_util/seqno.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/c0snr_set.h>

#include <hse_ikvdb/limits.h>

#include <syscall.h>
#include <semaphore.h>

struct c0snr_set {
};

/* The bucket mask is indexed by the number of active transactions
 * to obtain a bitmask used to constrain the number of buckets
 * available to c0snr_set_insert().  Keeping the number of
 * buckets reasonably constrained w.r.t the number of active ctxns
 * reduces the overhead required to maintain the horizon.
 */
static const u8 c0snr_set_bkt_maskv[] = {
    3, 3, 3, 3, 7, 7, 7, 7, 7, 7, 7, 15, 15, 15, 15, 15
};

/**
 * struct c0snr_set_bkt -
 * @csb_list:           ptr to the c0snr_set_list object
 */
struct c0snr_set_bkt {
    struct c0snr_set_list *csb_list;
};

/**
 * struct c0snr_set_impl -
 * @css_handle:         opaque handle for this struct
 * @css_active:         count of active c0snrs
 * @css_bktv:           active c0snr buckets
 */
struct c0snr_set_impl {
    struct c0snr_set        css_handle;
    u8                      css_maskv[NELEM(c0snr_set_bkt_maskv)];

    struct {
        atomic_t css_active __aligned(SMP_CACHE_BYTES * 2);
    } css_nodev[2];

    struct c0snr_set_bkt css_bktv[] __aligned(SMP_CACHE_BYTES * 2);
};

#define c0snr_set_h2r(handle) container_of(handle, struct c0snr_set_impl, css_handle)

struct c0snr_set_entry;

/**
 * struct c0snr_set_entry -
 * @cse_list:           ptr to the c0snr_set_list object
 * @cse_ctxn:           handle to the transaction (if active)
 * @cse_active:         ptr to css_active (tracks number of active c0snrs)
 * @cse_kvms_gen:       last active kvms gen to use this c0snr
 * @cse_refcnt:         reference count (txn, kvms acquire refs)
 */
struct c0snr_set_entry {
    struct c0snr_set_list      *cse_list;
    volatile struct kvdb_ctxn  *cse_ctxn;
    atomic_t                   *cse_active;
    u64                         cse_kvms_gen;

    union {
        uintptr_t   cse_c0snr;
        void       *cse_next;
    };

    atomic_t           cse_refcnt  __aligned(SMP_CACHE_BYTES);
};

#define KVMS_GEN_INVALID   (~0UL)
#define priv_to_c0snr_set_entry(ptr) container_of(ptr, struct c0snr_set_entry, cse_c0snr)

/**
 * struct c0snr_set_list
 * @act_lock:   lock protecting the list
 * @act_cache:  head of entry cache free list
 * @act_entryv: fixed-size cache of entry objects
 */
struct c0snr_set_list {
    spinlock_t              act_lock __aligned(SMP_CACHE_BYTES * 2);
    sem_t                   act_sema;

    /* Abort handler can go away when LC is in place */
    c0snr_set_abort_func   *css_abort_func;

    struct c0snr_set_entry  *act_cache;
    struct c0snr_set_entry   act_entryv[];
};

static struct c0snr_set_entry *
c0snr_set_entry_alloc(struct c0snr_set_entry **entry_listp)
{
    struct c0snr_set_entry *entry;

    entry = *entry_listp;
    assert(atomic_read(&entry->cse_refcnt) == 0);
    entry->cse_kvms_gen = KVMS_GEN_INVALID;
    if (entry) {
        *entry_listp = entry->cse_next;
    }

    return entry;
}

static void
c0snr_set_entry_free(struct c0snr_set_entry **entry_listp, struct c0snr_set_entry *entry)
{
    entry->cse_next = *entry_listp;
    *entry_listp = entry;
}

static void
c0snr_set_abort_fn(struct kvdb_ctxn *ctxn)
{
}

merr_t
c0snr_set_list_create(u32 max_elts, u32 index, struct c0snr_set_list **tree)
{
    struct c0snr_set_list *self;
    size_t                   sz;
    int                      i;

    sz = sizeof(*self);
    sz += sizeof(self->act_entryv[0]) * max_elts;

    self = alloc_aligned(sz, __alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sz);

    for (i = 0; i < max_elts; ++i)
        self->act_entryv[i].cse_next = self->act_entryv + i + 1;

    self->act_entryv[i - 1].cse_next = NULL;
    self->act_cache = self->act_entryv;

    spin_lock_init(&self->act_lock);
    sem_init(&self->act_sema, 0, 4);

    *tree = self;

    return 0;
}

void
c0snr_set_list_destroy(struct c0snr_set_list *self)
{
    sem_destroy(&self->act_sema);
    free_aligned(self);
}

merr_t
c0snr_set_create(c0snr_set_abort_func *afunc, struct c0snr_set **handle)
{
    struct c0snr_set_impl *self;

    u32    max_elts = HSE_C0SNRSET_ELTS_MAX;
    u32    max_bkts;
    merr_t err = 0;
    size_t sz;
    int    i;

    max_bkts = NELEM(self->css_maskv);

    sz = sizeof(*self);
    sz += sizeof(self->css_bktv[0]) * max_bkts;

    self = alloc_aligned(sz, __alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sz);
    memcpy(self->css_maskv, c0snr_set_bkt_maskv, sizeof(self->css_maskv));

    for (i = 0; i < max_bkts; ++i) {
        struct c0snr_set_bkt *bkt = self->css_bktv + i;

        err = c0snr_set_list_create(max_elts, i, &bkt->csb_list);
        if (ev(err))
            break;

        bkt->csb_list->css_abort_func = afunc? afunc : c0snr_set_abort_fn;
    }

    atomic_set(&self->css_nodev[0].css_active, 0);
    atomic_set(&self->css_nodev[1].css_active, 0);

    *handle = &self->css_handle;

    if (err) {
        c0snr_set_destroy(*handle);
        *handle = NULL;
    }

    return err;
}

void
c0snr_set_destroy(struct c0snr_set *handle)
{
    struct c0snr_set_impl *self;
    int                          i;

    if (ev(!handle))
        return;

    self = c0snr_set_h2r(handle);

    for (i = 0; i < NELEM(c0snr_set_bkt_maskv); ++i) {
        struct c0snr_set_bkt *bkt = self->css_bktv + i;

        c0snr_set_list_destroy(bkt->csb_list);
    }

    free_aligned(self);
}

void *
c0snr_set_get_c0snr(struct c0snr_set *handle, struct kvdb_ctxn *ctxn)
{
    struct c0snr_set_impl  *self = c0snr_set_h2r(handle);
    struct c0snr_set_entry *entry;
    struct c0snr_set_list  *cslist;
    struct c0snr_set_bkt   *bkt;
    atomic_t               *active;
    sem_t                  *sema;
    uint                    idx;

    static __thread uint cpuid, nodeid, cnt;

    if (cnt++ % 16 == 0) {
        if (( syscall(SYS_getcpu, &cpuid, &nodeid, NULL) ))
            cpuid = nodeid = raw_smp_processor_id();
    }

    active = &self->css_nodev[nodeid & 1].css_active;

    idx = atomic_inc_return(active) / 2;
    if (idx > NELEM(c0snr_set_bkt_maskv) - 1)
        idx = NELEM(c0snr_set_bkt_maskv) - 1;

    bkt = self->css_bktv + (cpuid & self->css_maskv[idx]);
    cslist = bkt->csb_list;
    sema = NULL;

    if (!spin_trylock(&cslist->act_lock)) {
        if (idx > 4) {
            sema = &cslist->act_sema;
            if (sem_wait(sema))
                sema = NULL; /* Probably EINTR */
        }
        spin_lock(&cslist->act_lock);
    }

    if (!cslist || !cslist->act_cache)
        hse_log(HSE_ERR "gsr5: cache full");

    entry = c0snr_set_entry_alloc(&cslist->act_cache);
    if (ev(!entry)) {
        spin_unlock(&cslist->act_lock);
        if (sema)
            sem_post(sema);
        atomic_dec(active);
        return NULL;
    }

    spin_unlock(&cslist->act_lock);

    if (sema)
        sem_post(sema);

    entry->cse_ctxn = ctxn;
    entry->cse_list = cslist;
    entry->cse_active = active;

    assert(atomic_read(&entry->cse_refcnt) == 0);
    atomic_inc(&entry->cse_refcnt);

    entry->cse_c0snr = HSE_SQNREF_INVALID;

    return &entry->cse_c0snr;
}

void
c0snr_clear_txn(
    uintptr_t  *priv)
{
    struct c0snr_set_entry *entry;

    entry = priv_to_c0snr_set_entry(priv);

    /*
     * This entry is no longer used by the transaction.
     * The transaction has either committed or aborted.
     * However, other readers may still be holding references.
     */
    assert(entry->cse_ctxn);
    entry->cse_ctxn = NULL;

    c0snr_dropref(priv);
}

u64
c0snr_get_cgen(
    uintptr_t          *priv)
{
    struct c0snr_set_entry  *entry;

    entry = priv_to_c0snr_set_entry(priv);

    return entry->cse_kvms_gen;
}

void
c0snr_getref(
    uintptr_t          *priv,
    u64                 c0ms_gen)
{
    struct c0snr_set_entry  *entry;

    entry = priv_to_c0snr_set_entry(priv);

    if (entry->cse_kvms_gen != c0ms_gen) {
        atomic_inc(&entry->cse_refcnt);

        /* There can only be one txn thread actively inserting
         * and updating the txn priv entry's c0kvms generation. */
        assert(entry->cse_kvms_gen == KVMS_GEN_INVALID || c0ms_gen > entry->cse_kvms_gen);
        entry->cse_kvms_gen = c0ms_gen;
    }
}

void
c0snr_dropref(
    uintptr_t          *priv)
{
    struct c0snr_set_entry *entry;
    struct c0snr_set_list  *tree;
    atomic_t               *active;

    entry = priv_to_c0snr_set_entry(priv);

    if (atomic_dec_return(&entry->cse_refcnt) > 0)
        return;

    tree = entry->cse_list;
    active = entry->cse_active;

    /* All the readers are done, free the entry */
    spin_lock(&tree->act_lock);
    c0snr_set_entry_free(&tree->act_cache, entry);
    spin_unlock(&tree->act_lock);

    atomic_dec(active);
}

bool
c0snr_txn_is_active(
    uintptr_t  *priv)
{
    struct c0snr_set_entry         *entry;

    entry = priv_to_c0snr_set_entry(priv);
    return entry->cse_ctxn ? true : false;
}

void
c0snr_abort(
    uintptr_t  *priv)
{
    struct c0snr_set_entry         *entry;

    entry = priv_to_c0snr_set_entry(priv);

    /*
     * Attempt to abort the transaction that allocated this c0snr.
     * Multiple threads may attempt to abort or commit but only one will
     * acquire the transaction lock, run to completion and clear cse_ctxn.
     */
    while (entry->cse_ctxn) {
        entry->cse_list->css_abort_func((struct kvdb_ctxn *)entry->cse_ctxn);

        cpu_relax();
    }
}
