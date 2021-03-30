/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include "_config.h"

#include <stdalign.h>

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
#include <hse_util/vlb.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/c0snr_set.h>

#include <hse_ikvdb/limits.h>

#include <syscall.h>

struct c0snr_set {
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
 * @css_bktv:           active c0snr buckets
 */
struct c0snr_set_impl {
    struct c0snr_set     css_handle;
    struct c0snr_set_bkt css_bktv[16];
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

#define c0snr_set_h2r(handle) container_of(handle, struct c0snr_set_impl, css_handle)

struct c0snr_set_entry;

/**
 * struct c0snr_set_entry -
 * @cse_list:           ptr to the c0snr_set_list object
 * @cse_ctxn:           handle to the transaction (if active)
 * @cse_kvms_gen:       last active kvms gen to use this c0snr
 * @cse_refcnt:         reference count (txn, kvms acquire refs)
 */
struct c0snr_set_entry {
    atomic_t                    cse_refcnt;
    struct c0snr_set_list      *cse_list;
    volatile struct kvdb_ctxn  *cse_ctxn;
    u64                         cse_kvms_gen;

    union {
        uintptr_t   cse_c0snr;
        void       *cse_next;
    };
} HSE_ALIGNED(SMP_CACHE_BYTES);

#define KVMS_GEN_INVALID   (~0UL)
#define priv_to_c0snr_set_entry(ptr) container_of(ptr, struct c0snr_set_entry, cse_c0snr)

/**
 * struct c0snr_set_list
 * @act_lock:      lock protecting the list
 * @act_index:     index into css_bktv[]
 * @act_cache:     head of entry cache free list
 * @act_entryc:    number of entries allocated from act_entryv[]
 * @act_entrymax:  max number of entries in act_entryv[]
 * @act_entryv:    fixed-size cache of entry objects
 * @act_memsz:     size of act_mem buffer
 * @act_mem:       base of memory allocation that contains self
 */
struct c0snr_set_list {
    spinlock_t              act_lock;
    uint                    act_index;
    struct c0snr_set_entry *act_cache;
    uint                    act_entryc;
    uint                    act_entrymax;

    /* Abort handler can go away when LC is in place */
    c0snr_set_abort_func   *css_abort_func;

    size_t                  act_memsz;
    void                   *act_mem;

    struct c0snr_set_entry  act_entryv[];
};

/* c0snr_set_entry_alloc() performs a one-time initialization
 * of the entry the first time it is allocated.  Subsequent
 * allocations return the entry unperturbed from the state
 * it was in when it was freed.
 */
static struct c0snr_set_entry *
c0snr_set_entry_alloc(struct c0snr_set_list *csl)
{
    struct c0snr_set_entry *entry;

    entry = csl->act_cache;
    if (entry) {
        assert(atomic_read(&entry->cse_refcnt) == 0);
        csl->act_cache = entry->cse_next;
        return entry;
    }

    if (csl->act_entryc < csl->act_entrymax) {
        entry = csl->act_entryv + csl->act_entryc++;
        entry->cse_list = csl;
        atomic_set(&entry->cse_refcnt, 0);
        return entry;
    }

    return NULL;
}

static void
c0snr_set_entry_free(struct c0snr_set_list *csl, struct c0snr_set_entry *entry)
{
    entry->cse_next = csl->act_cache;
    csl->act_cache = entry;
}

static void
c0snr_set_abort_fn(struct kvdb_ctxn *ctxn)
{
}

merr_t
c0snr_set_list_create(u32 max_elts, u32 index, struct c0snr_set_list **tree)
{
    struct c0snr_set_list *self;
    size_t sz;
    void *mem;

    sz = sizeof(*self) + sizeof(self->act_entryv[0]) * max_elts;
    sz += alignof(*self) * 8;
    sz = roundup(sz, 4ul << 20);

    mem = vlb_alloc(sz);
    if (ev(!mem))
        return merr(ENOMEM);

    /* Mitigate cacheline aliasing by offsetting into mem some number of
     * cache lines, then recompute max_elts based on the remaining space.
     */
    self = mem + alignof(*self) * (index % 8);
    max_elts = (sz - ((void *)self->act_entryv - mem)) / sizeof(self->act_entryv[0]);

    memset(self, 0, sizeof(*self));
    spin_lock_init(&self->act_lock);
    self->act_index = index;
    self->act_entrymax = max_elts;
    self->act_mem = mem;
    self->act_memsz = sz;

    *tree = self;

    return 0;
}

void
c0snr_set_list_destroy(struct c0snr_set_list *self)
{
    vlb_free(self->act_mem, self->act_memsz);
}

merr_t
c0snr_set_create(c0snr_set_abort_func *afunc, struct c0snr_set **handle)
{
    struct c0snr_set_impl *self;

    u32    max_elts = HSE_C0SNRSET_ELTS_MAX;
    u32    max_bkts;
    merr_t err = 0;
    int    i;

    max_bkts = NELEM(self->css_bktv);

    self = alloc_aligned(sizeof(*self), alignof(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));

    for (i = 0; i < max_bkts; ++i) {
        struct c0snr_set_bkt *bkt = self->css_bktv + i;

        err = c0snr_set_list_create(max_elts, i, &bkt->csb_list);
        if (ev(err))
            break;

        bkt->csb_list->css_abort_func = afunc? afunc : c0snr_set_abort_fn;
    }

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
    int i;

    if (ev(!handle))
        return;

    self = c0snr_set_h2r(handle);

    for (i = 0; i < NELEM(self->css_bktv); ++i) {
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

    static thread_local uint cpuid, nodeid, cnt;

    if (cnt++ % 16 == 0) {
        if (( syscall(SYS_getcpu, &cpuid, &nodeid, NULL) ))
            cpuid = nodeid = raw_smp_processor_id();
    }

    bkt = self->css_bktv + (nodeid & 1) * (NELEM(self->css_bktv) / 2);
    bkt += cpuid % (NELEM(self->css_bktv) / 2);
    cslist = bkt->csb_list;

    spin_lock(&cslist->act_lock);
    entry = c0snr_set_entry_alloc(cslist);
    spin_unlock(&cslist->act_lock);

    if (ev(!entry))
        return NULL;

    entry->cse_ctxn = ctxn;
    entry->cse_kvms_gen = KVMS_GEN_INVALID;
    entry->cse_c0snr = HSE_SQNREF_INVALID;

    assert(atomic_read(&entry->cse_refcnt) == 0);
    atomic_inc(&entry->cse_refcnt);

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

    entry = priv_to_c0snr_set_entry(priv);

    if (atomic_dec_return(&entry->cse_refcnt) > 0)
        return;

    tree = entry->cse_list;

    /* All the readers are done, free the entry */
    spin_lock(&tree->act_lock);
    c0snr_set_entry_free(tree, entry);
    spin_unlock(&tree->act_lock);
}

void
c0snr_droprefv(int refc, uintptr_t **refv)
{
    struct c0snr_set_impl *self;
    int i;

    struct bkt {
        struct c0snr_set_entry **tailp;
        struct c0snr_set_entry  *head;
    } *bkt, bktv[NELEM(self->css_bktv)];

    for (bkt = bktv; bkt < bktv + NELEM(bktv); ++bkt) {
        bkt->tailp = &bkt->head;
        *bkt->tailp = NULL;
    }

    for (i = 0; i < refc; ++i) {
        if (refv[i]) {
            struct c0snr_set_entry *entry;

            entry = priv_to_c0snr_set_entry(refv[i]);

            if (atomic_dec_return(&entry->cse_refcnt) > 0)
                continue;

            /* All the readers are done, append the entry to the
             * appropriate list.  We'll return them all to their
             * respective cache buckets en masse in order to
             * reduce contention on the list locks.
             */
            bkt = bktv + entry->cse_list->act_index;
            *bkt->tailp = entry;
            bkt->tailp = (void *)&entry->cse_next;
        }
    }

    for (bkt = bktv; bkt < bktv + NELEM(bktv); ++bkt) {
        if (bkt->head) {
            struct c0snr_set_list *csl;

            csl = bkt->head->cse_list;

            spin_lock(&csl->act_lock);
            *bkt->tailp = csl->act_cache;
            csl->act_cache = bkt->head;
            spin_unlock(&csl->act_lock);
        }
    }
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
