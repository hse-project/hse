/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/minmax.h>
#include <hse_util/spinlock.h>
#include <hse_util/assert.h>
#include <hse_util/log2.h>
#include <hse_util/page.h>
#include <hse_util/seqno.h>
#include <hse/error/merr.h>
#include <hse_util/vlb.h>
#include <hse_util/event_counter.h>

#include <hse_ikvdb/c0snr_set.h>

#include <hse_ikvdb/limits.h>

/* clang-format off */

#define c0snr_set_h2r(_handle) \
    container_of(_handle, struct c0snr_set_impl, css_handle)

#define priv_to_c0snr_set_entry(_priv) \
    container_of(_priv, struct c0snr_set_entry, cse_c0snr)

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
} HSE_ACP_ALIGNED;

struct c0snr_set_entry;

/**
 * struct c0snr_set_entry -
 * @cse_refcnt:         reference count (txn, kvms and lc acquire refs)
 * @cse_list:           ptr to the c0snr_set_list object
 * @cse_kvms_gen:       last active kvms gen to use this c0snr
 */
struct c0snr_set_entry {
    atomic_int             cse_refcnt;
    volatile bool          cse_ctxn;
    struct c0snr_set_list *cse_list;
    u64                    cse_kvms_gen;

    union {
        uintptr_t cse_c0snr;
        void     *cse_next;
    };
};

/**
 * struct c0snr_set_list - c0 sequence number reference set list
 * @act_lock:      lock protecting the list
 * @act_vlbsz:     size of act_vlb
 * @act_vlb:       address of the very-large-buffer which contains the c0snr_set
 * @act_index:     index into css_bktv[]
 * @act_cache:     head of entry cache free list
 * @act_entryc:    number of entries allocated from act_entryv[]
 * @act_entrymax:  max number of entries in act_entryv[]
 * @act_entryv:    fixed-size cache of entry objects
 */
struct c0snr_set_list {
    spinlock_t              act_lock;
    size_t                  act_vlbsz;
    void                   *act_vlb;

    uint                    act_index HSE_L1D_ALIGNED;
    struct c0snr_set_entry *act_cache;
    uint                    act_entryc;
    uint                    act_entrymax;

    struct c0snr_set_entry  act_entryv[] HSE_ACP_ALIGNED;
};

/* clang-format on */

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

merr_t
c0snr_set_list_create(u32 max_elts, u32 index, struct c0snr_set_list **tree)
{
    struct c0snr_set_list *self;
    size_t                 sz;
    void *                 vlb;

    sz = sizeof(*self) + sizeof(self->act_entryv[0]) * max_elts;
    sz += __alignof__(*self) * 8;
    sz = roundup(sz, 4ul << 20);

    vlb = vlb_alloc(sz);
    if (ev(!vlb))
        return merr(ENOMEM);

    /* Mitigate cacheline aliasing by offsetting into mem some number of
     * cache lines, then recompute max_elts based on the remaining space.
     */
    self = vlb + __alignof__(*self) * (index % 8);
    max_elts = (sz - ((void *)self->act_entryv - vlb)) / sizeof(self->act_entryv[0]);

    memset(self, 0, sizeof(*self));
    spin_lock_init(&self->act_lock);
    self->act_index = index;
    self->act_entrymax = max_elts;
    self->act_vlb = vlb;
    self->act_vlbsz = sz;

    *tree = self;

    return 0;
}

void
c0snr_set_list_destroy(struct c0snr_set_list *self)
{
    vlb_free(self->act_vlb, self->act_vlbsz);
}

merr_t
c0snr_set_create(struct c0snr_set **handle)
{
    struct c0snr_set_impl *self;
    u32                    max_elts, max_bkts;
    merr_t                 err = 0;
    int                    i;

    max_bkts = NELEM(self->css_bktv);
    max_elts = HSE_C0SNRSET_ELTS_MAX / max_bkts;

    self = alloc_aligned(sizeof(*self), __alignof__(*self));
    if (ev(!self))
        return merr(ENOMEM);

    memset(self, 0, sizeof(*self));

    for (i = 0; i < max_bkts; ++i) {
        struct c0snr_set_bkt *bkt = self->css_bktv + i;

        err = c0snr_set_list_create(max_elts, i, &bkt->csb_list);
        if (ev(err))
            break;
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
    int                    i;

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
    struct c0snr_set_impl * self = c0snr_set_h2r(handle);
    struct c0snr_set_entry *entry;
    struct c0snr_set_list * cslist;
    struct c0snr_set_bkt *  bkt;
    uint                    cpu, node;
    uint                    tries;

    cpu = hse_getcpu(&node);

    bkt = self->css_bktv + (node % 2) * (NELEM(self->css_bktv) / 2);
    bkt += (cpu / 2) % (NELEM(self->css_bktv) / 2);
    tries = NELEM(self->css_bktv);

    while (tries-- > 0) {
        cslist = bkt->csb_list;

        spin_lock(&cslist->act_lock);
        entry = c0snr_set_entry_alloc(cslist);
        spin_unlock(&cslist->act_lock);

        if (entry) {
            entry->cse_ctxn = !!ctxn;
            entry->cse_kvms_gen = KVMS_GEN_INVALID;
            entry->cse_c0snr = HSE_SQNREF_INVALID;

            assert(atomic_read(&entry->cse_refcnt) == 0);
            atomic_inc(&entry->cse_refcnt);

            return &entry->cse_c0snr;
        }

        /* Try the next bucket...
         */
        if (++bkt >= self->css_bktv + NELEM(self->css_bktv))
            bkt = self->css_bktv;
        ev(1);
    }

    return NULL;
}

void
c0snr_clear_txn(uintptr_t *priv)
{
    struct c0snr_set_entry *entry;

    entry = priv_to_c0snr_set_entry(priv);

    /*
     * This entry is no longer used by the transaction.
     * The transaction has either committed or aborted.
     * However, other readers may still be holding references.
     */
    assert(entry->cse_ctxn);
    entry->cse_ctxn = false;

    c0snr_dropref(priv);
}

u64
c0snr_get_cgen(uintptr_t *priv)
{
    struct c0snr_set_entry *entry;

    entry = priv_to_c0snr_set_entry(priv);

    return entry->cse_kvms_gen;
}

void
c0snr_getref(uintptr_t *priv, u64 c0ms_gen)
{
    struct c0snr_set_entry *entry;

    entry = priv_to_c0snr_set_entry(priv);

    if (c0ms_gen == KVMS_GEN_INVALID) {
        atomic_inc(&entry->cse_refcnt);
        return;
    }

    if (entry->cse_kvms_gen != c0ms_gen) {
        atomic_inc(&entry->cse_refcnt);

        /* There can only be one txn thread actively inserting
         * and updating the txn priv entry's c0kvms generation.
         */
        assert(entry->cse_kvms_gen == KVMS_GEN_INVALID || c0ms_gen > entry->cse_kvms_gen);
        entry->cse_kvms_gen = c0ms_gen;
    }
}

void
c0snr_dropref(uintptr_t *priv)
{
    struct c0snr_set_entry *entry;
    struct c0snr_set_list * tree;

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
    int                    i;

    struct bkt {
        struct c0snr_set_entry **tailp;
        struct c0snr_set_entry * head;
    } * bkt, bktv[NELEM(self->css_bktv)];

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
            ev(1);
        }
    }
    ev(1);
}

bool
c0snr_txn_is_active(uintptr_t *priv)
{
    struct c0snr_set_entry *entry = priv_to_c0snr_set_entry(priv);

    return entry->cse_ctxn;
}
