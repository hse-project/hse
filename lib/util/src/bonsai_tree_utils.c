/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "bonsai_tree_pvt.h"

static struct bonsai_slab *noslab = (void *)-1;

uint
bn_gc_reclaim(struct bonsai_root *tree, struct bonsai_slab *slab)
{
    uint nreclaimed = 0, i;
    uint32_t rcugen;

    rcugen = atomic_read_acq(&tree->br_gc_rcugen_done);

    /* Don't bother scanning if the rcu generation hasn't changed
     * since the last time we tried...
     */
    if (slab->bs_rcugen >= rcugen)
        return 0;

    slab->bs_rcugen = rcugen;

    for (i = slab->bs_entryc; i < HSE_BT_NODESPERSLAB; ++i) {
        struct bonsai_node *node = slab->bs_entryv + i;

        if (node->bn_rcugen < rcugen) {
            node->bn_rcugen = HSE_BN_RCUGEN_FREE;
            node->bn_left = slab->bs_rnodes;
            slab->bs_rnodes = node;
            ++nreclaimed;
            continue;
        }
    }

    return nreclaimed;
}

static void
bn_gc_sched_rcu_cb(struct rcu_head *arg)
{
    struct bonsai_root *tree = container_of(arg, typeof(*tree), br_gc_sched_rcu);
    struct bonsai_slab *slab, *next;
    uint64_t tstart, tstop;
    uint32_t rcugen;
    bool scheduled;
    int i;

    tstart = get_time_ns();
    tree->br_gc_latsum_gp += tstart - tree->br_gc_latstart;

    rcugen = atomic_read(&tree->br_gc_rcugen_start);

    /* [HSE_REVISIT] The 32 bit rcu generation counter cannot overflow for c0,
     * but maybe for LC (after a few years of non-stop rcu callbacks).
     */
    if (rcugen >= HSE_BN_RCUGEN_MAX) {
        assert(rcugen < HSE_BN_RCUGEN_MAX);
        abort();
    }

    atomic_set_rel(&tree->br_gc_rcugen_done, rcugen);

    /* There are likely many other rcu callbacks waiting to run on this
     * (probably one and only) rcu callback thread so we want to finish
     * as fast as possible.  Unfortunately, we must rescan a large
     * number of low quality slabs from the hold queue in an attempt
     * to prevent rampant allocation of new slabs.
     */
    next = (tree->br_gc_readyq == noslab) ? NULL : tree->br_gc_readyq;

    for (i = 0; i < (tree->br_gc_holdqc / 4) + 1; ++i) {
        slab = list_first_entry_or_null(&tree->br_gc_holdq, typeof(*slab), bs_entry);
        if (!slab)
            break;

        list_del(&slab->bs_entry);
        slab->bs_next = next;
        next = slab;
    }

    tree->br_gc_holdqc -= i;

    while (( slab = next )) {
        struct bonsai_slabinfo *slabinfo = slab->bs_slabinfo;

        next = slab->bs_next;

        slabinfo->bsi_rnodec += slab->bs_rnodec;
        slabinfo->bsi_nodec += slab->bs_nodec;
        slab->bs_rnodec = 0;
        slab->bs_nodec = 0;

        if (slab->bs_vfkeys) {
            slab->bs_vfkeys->bkv_next = tree->br_gc_vfkeys;
            tree->br_gc_vfkeys = slab->bs_vfkeys;
            slab->bs_vfkeys = NULL;
        }

        /* If we reclaim a sufficient number of nodes we return the
         * slab to the slabinfo free queue for reuse.  Otherwise,
         * we put it on the hold queue and we'll rescan it later.
         */
        if (bn_gc_reclaim(tree, slab) > 0) {
            spin_lock(&slabinfo->bsi_lock);
            list_add_tail(&slab->bs_entry, &slabinfo->bsi_freeq);
            spin_unlock(&slabinfo->bsi_lock);

            continue;
        }

        list_add_tail(&slab->bs_entry, &tree->br_gc_holdq);
        tree->br_gc_holdqc++;
    }

    tstop = get_time_ns();
    tree->br_gc_latsum_gc += tstop - tstart;

    /* Reschedule the callback if there are pending requests.
     */
    spin_lock(&tree->br_gc_lock);
    if (tree->br_gc_vfkeys && !tree->br_rfkeys) {
        tree->br_rfkeys = tree->br_gc_vfkeys;
        tree->br_gc_vfkeys = NULL;
    }

    tree->br_gc_readyq = tree->br_gc_waitq;

    scheduled = tree->br_gc_readyq;
    if (scheduled) {
        tree->br_gc_waitq = NULL;
        scheduled = true;

        atomic_inc_acq(&tree->br_gc_rcugen_start);
        tree->br_gc_latstart = tstop;
    }
    spin_unlock(&tree->br_gc_lock);

    if (scheduled)
        call_rcu(&tree->br_gc_sched_rcu, bn_gc_sched_rcu_cb);
}

static void
bn_gc_sched_rcu_noslab(struct bonsai_root *tree)
{
    bool scheduled;

    spin_lock(&tree->br_gc_lock);
    scheduled = !tree->br_gc_readyq;
    if (scheduled) {
        tree->br_gc_readyq = noslab;

        atomic_inc_acq(&tree->br_gc_rcugen_start);
        tree->br_gc_latstart = get_time_ns();
    }
    spin_unlock(&tree->br_gc_lock);

    if (scheduled)
        call_rcu(&tree->br_gc_sched_rcu, bn_gc_sched_rcu_cb);
}

static void
bn_gc_sched_rcu(struct bonsai_root *tree, struct bonsai_slab *slab)
{
    bool scheduled;

    spin_lock(&tree->br_gc_lock);
    slab->bs_next = tree->br_gc_waitq;
    tree->br_gc_waitq = slab;

    if (!tree->br_cheap) {
        if (tree->br_vfkeys) {
            assert(!slab->bs_vfkeys);
            slab->bs_vfkeys = tree->br_vfkeys;
            tree->br_vfkeys = NULL;
        }
    }

    /* Schedule an rcu callback if one isn't already scheduled.
     */
    scheduled = !tree->br_gc_readyq;
    if (scheduled) {
        tree->br_gc_readyq = tree->br_gc_waitq;
        tree->br_gc_waitq = NULL;

        atomic_inc_acq(&tree->br_gc_rcugen_start);
        tree->br_gc_latstart = get_time_ns();
    }
    spin_unlock(&tree->br_gc_lock);

    if (scheduled)
        call_rcu(&tree->br_gc_sched_rcu, bn_gc_sched_rcu_cb);
}

static struct bonsai_slab *
bn_gc_sched(struct bonsai_root *tree, struct bonsai_slab *slab)
{
    struct bonsai_slabinfo *slabinfo = slab->bs_slabinfo;

    if (bn_gc_reclaim(tree, slab) > 0)
        return slab;

    bn_gc_sched_rcu(tree, slab);

    /* Try to pop a slab off the free queue (i.e., the free queue is a list
     * of slabs that contain nodes reclaimed by the gc).
     */
    spin_lock(&slabinfo->bsi_lock);
    slab = list_first_entry_or_null(&slabinfo->bsi_freeq, typeof(*slab), bs_entry);
    if (slab) {
        list_del(&slab->bs_entry);
        slabinfo->bsi_slab = slab;
    }
    spin_unlock(&slabinfo->bsi_lock);

    return slab;
}

struct bonsai_slab *
bn_slab_init(struct bonsai_slab *slab, struct bonsai_slabinfo *slabinfo, bool canfree)
{
    memset(slab, 0, sizeof(*slab));
    slab->bs_entryc = HSE_BT_NODESPERSLAB;
    slab->bs_canfree = canfree;
    slab->bs_slabinfo = slabinfo;

    slabinfo->bsi_slab = slab;
    slabinfo->bsi_slabc++;

    return slab;
}

static struct bonsai_slab *
bn_slab_alloc(struct bonsai_root *tree, struct bonsai_slabinfo *slabinfo)
{
    struct bonsai_slab *slab;
    bool canfree;

    if (tree->br_cheap) {
        slab = cheap_memalign(tree->br_cheap, alignof(*slab), HSE_BT_SLABSZ);
        canfree = false;
    } else {
        slab = aligned_alloc(alignof(*slab), HSE_BT_SLABSZ);
        canfree = true;
    }

    return slab ? bn_slab_init(slab, slabinfo, canfree) : NULL;
}

void
bn_slab_free(struct bonsai_slab *slab)
{
    if (slab) {
        bn_kv_free(slab->bs_vfkeys);

        if (slab->bs_canfree)
            free(slab);
    }
}

static struct bonsai_node *
bn_node_alloc_impl(struct bonsai_root *tree, uint skidx)
{
    struct bonsai_slabinfo *slabinfo;
    struct bonsai_slab *slab;
    struct bonsai_node *node;

    slabinfo = tree->br_slabinfov + skidx;
    slab = slabinfo->bsi_slab;

    while (1) {
        node = slab->bs_rnodes;
        if (node) {
            slab->bs_rnodes = node->bn_left;
            slab->bs_rnodec++;

            return node;
        }

        if (slab->bs_entryc > 0)
            break;

        slab = bn_gc_sched(tree, slab);
        if (slab)
            continue;

        slab = bn_slab_alloc(tree, slabinfo);
        if (slab)
            break;

        /* If the current slab is the OOM slab it means we've been
         * here before and we're unable to allocate memory for a new
         * node.  This should never happen, but if it does we can't
         * fail the node allocation request because that would corrupt
         * the tree if we're in the middle of a rebalance operation.
         */
        if (tree->br_oomslab) {
            if (slabinfo->bsi_slab == tree->br_oomslab->bsi_slab) {
                assert(slabinfo->bsi_slab != tree->br_oomslab->bsi_slab);
                abort();
            }
        }
        else {
            tree->br_oomslab = tree->br_rootslab + 1;

            /* Set bounds to prevent inserts into the tree after this one
             * completes.  There should be plenty of free nodes in the root
             * slab to complete a rebalance operation, so we share the root
             * slab with current skidx so that it always has a valid slab.
             */
            atomic_set(&tree->br_bounds, -1);
        }

        slab = tree->br_oomslab->bsi_slab;
        slabinfo->bsi_slab = slab;
    }

    slab->bs_nodec++;

    /* Brand new slabs tend to collect a lot of garbage on their
     * maiden voyage.  A few judiciously initiated reclaims help
     * to improve their per-page spatial density of active nodes.
     */
    if (slab->bs_entryc % 64 == 0) {
        if (bn_gc_reclaim(tree, slab) < 8)
            bn_gc_sched_rcu_noslab(tree);
    }

    return slab->bs_entryv + --slab->bs_entryc;
}

static struct bonsai_node *
bn_node_alloc(struct bonsai_root *tree, int height, uint skidx)
{
    /* Allocate the lowest nodes in the tree from the root slab such that
     * all the nodes in the first eight or nine levels of the tree typically
     * reside within the same three or four pages, leaving ample free space
     * to satisfy OOM allocations.
     */
    if (tree->br_height - height < 5)
        return bn_node_alloc_impl(tree, NELEM(tree->br_slabinfov) - 2);

    /* Otherwise allocate from a per-skidx slab to try and improve the
     * spatial density of nodes that share a common skidx (i.e, nodes
     * that are clustered in a subtree based on skidx).
     */
    return bn_node_alloc_impl(tree, skidx % (NELEM(tree->br_slabinfov) - 2));
}

static void *
bn_alloc(struct bonsai_root *tree, size_t sz)
{
    if (tree->br_cheap)
        return cheap_malloc(tree->br_cheap, sz);

    return malloc(sz);
}

static struct bonsai_val *
bn_val_init(struct bonsai_val *v, const struct bonsai_sval *sval, size_t sz)
{
    memset(v, 0, sizeof(*v));
    v->bv_seqnoref = sval->bsv_seqnoref;
    v->bv_value = sval->bsv_val;
    v->bv_xlen = sval->bsv_xlen;

    if (sz > sizeof(*v)) {
        memcpy(v->bv_valbuf, sval->bsv_val, sz - sizeof(*v));
        v->bv_value = v->bv_valbuf;
    }

    return v;
}

struct bonsai_val *
bn_val_alloc(struct bonsai_root *tree, const struct bonsai_sval *sval, bool managed)
{
    struct bonsai_val *v;
    size_t sz;

    sz = sizeof(*v);

    if (!managed)
        sz += bonsai_sval_vlen(sval);

    v = bn_alloc(tree, sz);
    if (v) {
        v = bn_val_init(v, sval, sz);
        tree->br_val_alloc++;
    }

    return v;
}

static void
bn_kv_free_vals(struct bonsai_kv *kv)
{
    struct bonsai_val *val, *embedded;

    /* The kv and initial val are allocated in one contiguous chunk
     * of memory, so we must prevent freeing the embedded value.
     */
    embedded = (void *)kv + kv->bkv_voffset;

    while (( val = kv->bkv_values )) {
        kv->bkv_values = val->bv_next;
        if (val != embedded)
            free(val);
    }

    while (( val = kv->bkv_freevals )) {
        kv->bkv_freevals = val->bv_free;
        if (val != embedded)
            free(val);
    }
}

void
bn_kv_free(struct bonsai_kv *kvlist)
{
    struct bonsai_kv *kv;

    while (( kv = kvlist )) {
        kvlist = kv->bkv_free;

        /* Torch the key ptr in case someone tries to use it
         * after it's been freed...
         */
        kv->bkv_key = (void *)0xbadcafe5badcafe5;
        bn_kv_free_vals(kv);
        free(kv);
    }
}

static merr_t
bn_kv_alloc(
    struct bonsai_root        *tree,
    const struct bonsai_skey  *skey,
    const struct bonsai_sval  *sval,
    struct bonsai_kv         **kv_out)
{
    struct bonsai_val *v;
    struct bonsai_kv *kv;
    size_t ksz, vsz;
    bool managed;
    u16 voffset;

    ksz = sizeof(*kv);
    vsz = sizeof(*v);

    managed = skey->bsk_flags & HSE_BTF_MANAGED;
    if (!managed) {
        ksz += key_imm_klen(&skey->bsk_key_imm);
        vsz += bonsai_sval_vlen(sval);
    }

    voffset = roundup(ksz, sizeof(uintptr_t));

    kv = bn_alloc(tree, voffset + vsz);
    if (!kv)
        return merr(ENOMEM);

    memset(kv, 0, sizeof(*kv));
    kv->bkv_key_imm = skey->bsk_key_imm;
    kv->bkv_key = (void *)skey->bsk_key; // [HSE_REVISIT] Constness...
    kv->bkv_voffset = voffset;

    if (ksz > sizeof(*kv)) {
        memcpy(kv->bkv_keybuf, skey->bsk_key, ksz - sizeof(*kv));
        kv->bkv_key = kv->bkv_keybuf;
    }

    v = (void *)kv + voffset;
    kv->bkv_values = bn_val_init(v, sval, vsz);

    tree->br_key_alloc++;

    *kv_out = kv;

    return 0;
}

static struct bonsai_node *
bn_node_make(
    struct bonsai_root *        tree,
    struct bonsai_node *        left,
    struct bonsai_node *        right,
    int                         height,
    struct bonsai_kv *          kv,
    const struct key_immediate *ki)
{
    struct bonsai_node *node;

    node = bn_node_alloc(tree, height, key_immediate_index(ki));
    if (node) {
        memset(node, 0, sizeof(*node));
        node->bn_key_imm = *ki;
        node->bn_left = left;
        node->bn_right = right;
        node->bn_height = height;
        node->bn_rcugen = HSE_BN_RCUGEN_ACTIVE;
        node->bn_kv = kv;
    }

    return node;
}

struct bonsai_node *
bn_kvnode_alloc(
    struct bonsai_root       *tree,
    const struct bonsai_skey *skey,
    const struct bonsai_sval *sval)
{
    struct bonsai_kv *kv = NULL;
    merr_t err;

    err = bn_kv_alloc(tree, skey, sval, &kv);
    if (err)
        return NULL;

    return bn_node_make(tree, NULL, NULL, 1, kv, &skey->bsk_key_imm);
}

struct bonsai_node *
bn_node_dup(struct bonsai_root *tree, struct bonsai_node *src)
{
    return bn_node_make(tree, src->bn_left, src->bn_right, src->bn_height, src->bn_kv, &src->bn_key_imm);
}

struct bonsai_node *
bn_node_dup_ext(
    struct bonsai_root *tree,
    struct bonsai_node *src,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    uint height = bn_height_max(bn_height_get(left), bn_height_get(right));

    return bn_node_make(tree, left, right, height, src->bn_kv, &src->bn_key_imm);
}
