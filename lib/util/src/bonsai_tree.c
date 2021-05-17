/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdalign.h>

#include <hse_util/log2.h>
#include <hse_util/logging.h>

#include "bonsai_tree_pvt.h"

#define BN_INSERT_FLAG_RIGHT    (0x01u)

static void
bn_summary(struct bonsai_root *tree)
{
#ifndef NDEBUG
    static thread_local uint bn_summary_calls_tls;
    int nodec = 0, rnodec = 0, slabc = 0, n, i;
    struct bonsai_slabinfo *slabinfo;
    struct bonsai_slab *slab;
    char buf[256];

    if (++bn_summary_calls_tls % 8 || !tree->br_root)
        return;

    n = snprintf(buf, sizeof(buf), "(%u %lu %3lu)",
                 atomic_read(&tree->br_gc_rcugen_done),
                 (tree->br_gc_latsum_gp / 1000000) / atomic_read(&tree->br_gc_rcugen_done),
                 (tree->br_gc_latsum_gc / 1000) / atomic_read(&tree->br_gc_rcugen_done));

    for (i = 0; i < NELEM(tree->br_slabinfov) && n < sizeof(buf); ++i) {
        slabinfo = tree->br_slabinfov + i;
        slab = slabinfo->bsi_slab;

        slabinfo->bsi_rnodec += slab->bs_rnodec;
        slabinfo->bsi_nodec += slab->bs_nodec;

        if (slabinfo->bsi_nodec > 0) {
            n += snprintf(buf + n, sizeof(buf) - n, "  %u,%u,%u,%u",
                          i, slabinfo->bsi_nodec, slabinfo->bsi_rnodec,
                          slabinfo->bsi_slabc);
        }

        rnodec += slabinfo->bsi_rnodec;
        nodec += slabinfo->bsi_nodec;
        slabc += slabinfo->bsi_slabc;
    }

    hse_log(HSE_NOTICE "%s: %2d %2d  keys %u  vals %u  nodes %u,%u,%u  %.2lf  %s",
            __func__, tree->br_height, atomic_read(&tree->br_bounds),
            tree->br_key_alloc, tree->br_val_alloc,
            nodec, rnodec, slabc,
            (double)(nodec + rnodec) / tree->br_key_alloc, buf);
#endif
}

static struct bonsai_node *
bn_ior_replace(
    struct bonsai_root *      tree,
    struct bonsai_node *      node,
    const struct bonsai_skey *skey,
    const struct bonsai_sval *sval)
{
    struct bonsai_val *oldv = NULL, *v;
    enum bonsai_ior_code code;

    v = bn_val_alloc(tree, sval, skey->bsk_flags & HSE_BTF_MANAGED);
    if (!v)
        return NULL;

    SET_IOR_REPORADD(code);

    tree->br_ior_cb(tree->br_ior_cbarg, &code, node->bn_kv, v, &oldv, tree->br_height);

    /* oldv must remain visible for the life of the kv since cursors
     * might use it long after dropping the rcu read lock.
     */
    if (oldv) {
        oldv->bv_free = node->bn_kv->bkv_freevals;
        node->bn_kv->bkv_freevals = oldv;
    }

    return node;
}

static struct bonsai_node *
bn_ior_insert(
    struct bonsai_root         *tree,
    struct bonsai_kv           *parent,
    const struct bonsai_skey   *skey,
    const struct bonsai_sval   *sval,
    u32                         flags)
{
    struct bonsai_node *node;
    enum bonsai_ior_code code;

    node = bn_kvnode_alloc(tree, skey, sval);
    if (!node)
        return NULL;

    if (flags & BN_INSERT_FLAG_RIGHT) {
        node->bn_kv->bkv_next = parent->bkv_next;
        node->bn_kv->bkv_prev = parent;
    } else {
        node->bn_kv->bkv_next = parent;
        node->bn_kv->bkv_prev = parent->bkv_prev;
    }

    rcu_assign_pointer(node->bn_kv->bkv_next->bkv_prev, node->bn_kv);
    rcu_assign_pointer(node->bn_kv->bkv_prev->bkv_next, node->bn_kv);

    SET_IOR_INS(code);
    tree->br_ior_cb(tree->br_ior_cbarg, &code, node->bn_kv, NULL, NULL, tree->br_height);

    return node;
}

/* For efficiency, bn_ior_impl() uses the least-significant bit
 * of the bonsai node pointer to remember which way it went when
 * searching for the insertion point.
 */
#define BN_IOR_RIGHT    ((uintptr_t)BN_INSERT_FLAG_RIGHT)
#define BN_IOR_MASK     ((uintptr_t)(sizeof(uintptr_t) - 1))

_Static_assert(BN_IOR_RIGHT > 0 && BN_IOR_RIGHT < BN_IOR_MASK,
               "bn_ior_impl() requires BN_INSERT_FLAG_RIGHT to be 1 or 2");

static struct bonsai_node *
bn_ior_impl(
    struct bonsai_root         *tree,
    struct bonsai_node         *node,
    const struct bonsai_skey   *skey,
    const struct bonsai_sval   *sval,
    struct bonsai_kv           *parent)
{
    const struct key_immediate *key_imm;
    uintptr_t stack[HSE_BT_HEIGHT_MAX];
    const void *key;
    u32 flags = 0;
    int n = 0;
    s32 res;

    key_imm = &skey->bsk_key_imm;
    key = skey->bsk_key;

    /* [HSE_REVISIT] For the time being no flags should be set.  If flags
     * is set it's likely the caller didn't initialize the ktuple correctly.
     */
    assert(skey->bsk_flags == 0);

    if (HSE_UNLIKELY( tree->br_height >= NELEM(stack) - HSE_BT_BALANCE_THRESHOLD )) {
        assert(tree->br_height < NELEM(stack) - HSE_BT_BALANCE_THRESHOLD);
        return NULL; /* shouldn't happen */
    }

    /* Find the position to insert or node to replace, keeping track
     * of all nodes visited and which way (left or right) we went...
     */
    while (node) {
        res = key_full_cmp(key_imm, key, &node->bn_key_imm, node->bn_kv->bkv_key);

        if (HSE_UNLIKELY(res == 0))
            break;

        if (res < 0) {
            stack[n++] = (uintptr_t)node;
            node = node->bn_left;
        } else {
            stack[n++] = (uintptr_t)node | BN_IOR_RIGHT;
            node = node->bn_right;
        }
    }

    if (HSE_UNLIKELY( n > NELEM(stack) )) {
        assert(n < NELEM(stack));
        abort(); /* should never ever happen */
    }

    if (n > 0) {
        struct bonsai_node *prev;

        if (n > tree->br_height)
            tree->br_height = n;

        flags = (stack[n - 1] & BN_IOR_MASK);
        prev = (void *)(stack[n - 1] & ~BN_IOR_MASK);
        parent = prev->bn_kv;
    }

    if (node) {
        node = bn_ior_replace(tree, node, skey, sval);

        return node ? tree->br_root : NULL;
    }

    node = bn_ior_insert(tree, parent, skey, sval, flags);
    if (!node)
        return NULL;

    /* Failure up to this point is safe in that the tree will not have been
     * modified.  However, failure to allocate a node during rebalancing does
     * leave the tree corrupted.  We now have in place a reserved slab that
     * should be sufficiently large to complete any rebalance operation,
     * after which we disallow subsequent inserts.
     */
    while (node && n-- > 0) {
        struct bonsai_node *prev;
        bool right;

        right = (stack[n] & BN_IOR_RIGHT);
        prev = (void *)(stack[n] & ~BN_IOR_MASK);

        assert(node->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);
        assert(prev->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);

        if (right)
            node = bn_balance_tree(tree, prev, prev->bn_left, node, key_imm, key, B_UPDATE_R);
        else
            node = bn_balance_tree(tree, prev, node, prev->bn_right, key_imm, key, B_UPDATE_L);
    }

    return node;
}

static inline struct bonsai_kv *
bn_find_next_pfx(struct bonsai_root *tree, const struct bonsai_skey *skey)
{
    struct bonsai_node *        node;
    struct bonsai_node *        mnode;
    const struct key_immediate *ki;
    const void *                key;

    uint klen;
    s32  res;
    u32  skidx;

    /* [HSE_REVISIT] Optimize using lcp */

    ki = &skey->bsk_key_imm;
    key = skey->bsk_key;
    klen = key_imm_klen(ki);
    skidx = key_immediate_index(ki);

    node = rcu_dereference(tree->br_root);
    mnode = NULL;

    while (node) {
        u32 node_skidx = key_immediate_index(&node->bn_kv->bkv_key_imm);

        res = skidx - node_skidx;
        if (res == 0)
            res = key_inner_cmp(key, klen, node->bn_kv->bkv_key, klen);

        if (res < 0) {
            mnode = node;
            node = rcu_dereference(node->bn_left);
        } else {
            node = rcu_dereference(node->bn_right);
        }
    }

    return mnode ? mnode->bn_kv : NULL;
}

static inline struct bonsai_kv *
bn_find_impl(struct bonsai_root *tree, const struct bonsai_skey *skey, enum bonsai_match_type mtype)
{
    struct bonsai_node *node, *node_le, *node_ge;
    const struct key_immediate *ki;
    const void *key;
    uint klen, lcp, bounds;
    s32  res;

    ki = &skey->bsk_key_imm;
    key = skey->bsk_key;
    klen = key_imm_klen(ki);
    lcp = KI_DLEN_MAX;

    /* Once the tree has been finalized we can safely compare the
     * search key to the bounds of the tree and/or leverage the
     * lcp to potentially minimize the amount of work required
     * to search for the key in this tree.
     *
     * Use acquire semantics here to prevent speculative reading
     * within the bounds block...
     */
    bounds = atomic_read_acq(&tree->br_bounds);
    if (bounds > 0) {
        struct bonsai_kv *bkv = rcu_dereference(tree->br_kv.bkv_prev); /* max key */

        /* br_bounds is set to 1 + the lcp to use. */
        lcp = min_t(uint, klen, bounds - 1);

        if (lcp > KI_DLEN_MAX &&
            key_immediate_index(ki) == key_immediate_index(&bkv->bkv_key_imm)) {

            lcp = memlcpq(key, bkv->bkv_key, lcp);
            if (lcp > KI_DLEN_MAX) {
                assert(key_immediate_cmp(ki, &bkv->bkv_key_imm) == S32_MIN);
                goto search;
            }
        }

        lcp = KI_DLEN_MAX;

        /*
         * If search key > max, then a miss for both GE and EQ get.
         * Return the max key for a LE get and a NULL for EQ get.
         */
        res = key_immediate_cmp(ki, &bkv->bkv_key_imm);
        if (res > 0)
            return (mtype == B_MATCH_LE) ? bkv : NULL;

        bkv = tree->br_kv.bkv_next; /* min key */

        /*
         * If search key < min and there's no more to compare, then
         * return the min key for a GE get and a NULL for EQ get.
         */
        res = key_immediate_cmp(ki, &bkv->bkv_key_imm);
        if (res < 0 && res > S32_MIN)
            return (mtype == B_MATCH_GE) ? bkv : NULL;
    }

search:
    key += lcp;
    klen -= lcp;

    node = rcu_dereference(tree->br_root);
    node_le = node_ge = NULL;

    while (node) {
        res = key_immediate_cmp(ki, &node->bn_key_imm);

        if (HSE_UNLIKELY(res == S32_MIN)) {
            assert(key_imm_klen(&node->bn_key_imm) >= lcp);

            /* At this point we are assured that both keys'
             * ki_dlen are greater than KI_DLEN_MAX.
             */
            res = key_inner_cmp(
                key, klen, node->bn_kv->bkv_key + lcp, key_imm_klen(&node->bn_key_imm) - lcp);
        }

        if (HSE_UNLIKELY(res == 0))
            return node->bn_kv;

        if (res < 0) {
            node_ge = node;
            node = rcu_dereference(node->bn_left);
        } else {
            node_le = node;
            node = rcu_dereference(node->bn_right);
        }
    }

    if (HSE_UNLIKELY(mtype == B_MATCH_LE))
        return node_le ? node_le->bn_kv : NULL;

    if (HSE_UNLIKELY(mtype == B_MATCH_GE))
        return node_ge ? node_ge->bn_kv : NULL;

    return NULL;
}

merr_t
bn_insert_or_replace(
    struct bonsai_root *      tree,
    const struct bonsai_skey *skey,
    const struct bonsai_sval *sval)
{
    struct bonsai_node *oldroot;
    struct bonsai_node *newroot;

    /* Reject attempts to modify the tree if has been finalized
     * (bounds > 0) or is out of memory (bounds < 0).
     */
    if (atomic_read(&tree->br_bounds))
        return merr(ENOMEM);

    oldroot = tree->br_root;

    /* [HSE_REVISIT] Need to revisit, newroot could be nil once we add
     * the capability to remove nodes.
     */
    newroot = bn_ior_impl(tree, oldroot, skey, sval, &tree->br_kv);
    if (!newroot)
        return merr(ENOMEM);

    if (newroot != oldroot) {
        assert(oldroot == tree->br_root);

        bn_gc_reclaim(tree, tree->br_rootslab->bsi_slab);

        rcu_assign_pointer(tree->br_root, newroot);
    }

    return 0;
}

bool
bn_find(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv)
{
    struct bonsai_kv *lkv;

    assert(kv);

    lkv = bn_find_impl(tree, skey, B_MATCH_EQ);
    if (lkv) {
        *kv = lkv;
        return true;
    }

    return false;
}

bool
bn_findGE(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv)
{
    struct bonsai_kv *lkv;

    assert(kv);

    lkv = bn_find_impl(tree, skey, B_MATCH_GE);
    if (lkv) {
        *kv = lkv;
        return true;
    }

    return false;
}

bool
bn_findLE(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv)
{
    struct bonsai_kv *lkv;

    assert(kv);

    lkv = bn_find_impl(tree, skey, B_MATCH_LE);
    if (lkv) {
        *kv = lkv;
        return true;
    }

    return false;
}

bool
bn_find_pfx_GT(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv)
{
    struct bonsai_kv *lkv;

    assert(kv);

    lkv = bn_find_next_pfx(tree, skey);
    if (lkv) {
        *kv = lkv;
        return true;
    }

    return false;
}

void
bn_finalize(struct bonsai_root *tree)
{
    const struct bonsai_kv *kmin, *kmax;
    uint                    lcp, set_lcp = 0;

    kmin = rcu_dereference(tree->br_kv.bkv_next);
    kmax = rcu_dereference(tree->br_kv.bkv_prev);

    /* If all the keys in the tree are sufficiently long then we
     * check to see if they have a common prefix.  If so, we can
     * leverage the longest common prefix to reduce the amount
     * of work required to find a key in bn_find_impl().
     */
    if (kmin != kmax) {
        lcp = min_t(uint, key_imm_klen(&kmin->bkv_key_imm), key_imm_klen(&kmax->bkv_key_imm));

        if (lcp > KI_DLEN_MAX &&
            key_immediate_index(&kmin->bkv_key_imm) == key_immediate_index(&kmax->bkv_key_imm)) {

            lcp = memlcpq(kmin->bkv_key, kmax->bkv_key, lcp);
            if (lcp > KI_DLEN_MAX) {
                assert(key_immediate_cmp(&kmin->bkv_key_imm, &kmax->bkv_key_imm) == S32_MIN);
                set_lcp = lcp;
            }
        }

        /* Indicate that the bounds have been established and the lcp to use. */
        atomic_set_rel(&tree->br_bounds, set_lcp + 1);
    }
}

static void
bn_reset_impl(struct bonsai_root *tree)
{
    struct bonsai_slab *slab;
    struct bonsai_kv *kv;

    if (!tree->br_root || tree->br_cheap)
        return;

    bn_kv_free(tree->br_gc_freekeys);
    bn_kv_free(tree->br_freekeys);

    /* Terminate the list of keys so that we can call bn_kv_free().
     */
    if ((kv = rcu_dereference(tree->br_kv.bkv_next)) != &tree->br_kv) {
        rcu_dereference(tree->br_kv.bkv_prev)->bkv_next = NULL;
        bn_kv_free(kv);
    }

    /* All slabs we allocated must be on one of these lists.  Freeing
     * all the slabs destroys all the nodes in the tree without ever
     * having to actually walk the tree.
     */
    struct bonsai_slab *slabv[] = {
        tree->br_gc_waitq, tree->br_gc_activeq, tree->br_gc_emptyq
    };

    assert(!tree->br_gc_readyq);

    for (int i = 0; i < NELEM(slabv); ++i) {
        while (( slab = slabv[i] )) {
            slabv[i] = slab->bs_next;
            bn_slab_free(slab);
        }
    }

    for (int i = 0; i < NELEM(tree->br_slabinfov); ++i) {
        struct bonsai_slabinfo *slabinfo = tree->br_slabinfov + i;

        while (( slab = slabinfo->bsi_freeq )) {
            slabinfo->bsi_freeq = slab->bs_next;

            bn_slab_free(slab);
        }

        bn_slab_free(slabinfo->bsi_slab);
    }
}

void
bn_reset(struct bonsai_root *tree)
{
    assert(tree->br_magic == tree);

    /* Wait for all rcu callbacks to complete.
     */
    while (rcu_dereference(tree->br_gc_readyq))
        rcu_barrier();

    bn_summary(tree);

    bn_reset_impl(tree);

    memset(&tree->br_height, 0, sizeof(*tree) - offsetof(struct bonsai_root, br_height));

    tree->br_kv.bkv_prev = &tree->br_kv;
    tree->br_kv.bkv_next = &tree->br_kv;

    spin_lock_init(&tree->br_gc_lock);
    atomic_set(&tree->br_gc_rcugen_start, 1);
    atomic_set(&tree->br_gc_rcugen_done, 1);

    for (int i = 0; i < NELEM(tree->br_slabinfov); ++i) {
        struct bonsai_slabinfo *slabinfo = tree->br_slabinfov + i;

        /* All slabinfo records must have a valid slab at all times.
         */
        slabinfo->bsi_slab0 = tree->br_slabbase + HSE_BT_SLABSZ * i;
        bn_slab_init(slabinfo->bsi_slab0, slabinfo, false);
    }

    atomic_set_rel(&tree->br_bounds, 0);

    rcu_assign_pointer(tree->br_root, NULL);
}

merr_t
bn_create(
    struct cheap        *cheap,
    bonsai_ior_cb        cb,
    void                *cbarg,
    struct bonsai_root **tree)
{
    struct bonsai_root *r;
    size_t sz;

    if (!cb || !tree)
        return merr(EINVAL);

    /* Include space for each per-skidx emedded slabs starting on a page
     * aligned boundary.
     */
    sz = sizeof(*r) + PAGE_SIZE + HSE_BT_SLABSZ * NELEM(r->br_slabinfov);

    if (cheap) {
        r = cheap_memalign(cheap, alignof(*r), sz);
    } else {
        r = aligned_alloc(alignof(*r), sz);
    }

    if (!r)
        return merr(ENOMEM);

    memset(r, 0, sizeof(*r));
    r->br_cheap = cheap;
    r->br_ior_cb = cb;
    r->br_ior_cbarg = cbarg;
    r->br_slabbase = (r + 1);
    r->br_slabbase = PTR_ALIGN(r->br_slabbase, PAGE_SIZE);
    r->br_rootslab = r->br_slabinfov + NELEM(r->br_slabinfov) - 1;
    r->br_magic = r;

    bn_reset(r);

    *tree = r;

    return 0;
}

void
bn_destroy(struct bonsai_root *tree)
{
    if (!tree)
        return;

    bn_reset(tree);

    assert(tree->br_magic == tree);
    tree->br_magic = (void *)0xbadcafe3badcafe1;

    if (!tree->br_cheap)
        free(tree);
}

__attribute__((__cold__))
static void
bn_traverse_impl(struct bonsai_node *node)
{
    if (!node)
        return;

    assert(node->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);

    bn_traverse_impl(rcu_dereference(node->bn_left));
    bn_traverse_impl(rcu_dereference(node->bn_right));
}

__attribute__((__cold__))
void
bn_traverse(struct bonsai_root *tree)
{
    bn_traverse_impl(rcu_dereference(tree->br_root));
}
