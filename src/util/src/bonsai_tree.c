/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>

#include "bonsai_tree_pvt.h"

#define BN_INSERT_FLAG_RIGHT 1
#define BN_INSERT_FLAG_TOMB 2

static inline struct bonsai_node *
bn_update(
    struct bonsai_root *      tree,
    struct bonsai_node *      node,
    const struct bonsai_sval *sval,
    u32                       flags)
{
    struct bonsai_val *  v;
    struct bonsai_val *  oldv;
    enum bonsai_ior_code code;

    /* Invalidate the tombspan, if any. */
    if (unlikely(!(flags & BN_INSERT_FLAG_TOMB) && node->bn_kv->bkv_tomb)) {
        node->bn_kv->bkv_tomb->bkv_tomb = NULL;
        node->bn_kv->bkv_tomb = NULL;
    }

    v = bn_val_alloc(tree, sval);
    if (ev(!v))
        return NULL;

    SET_IOR_REPORADD(code);
    oldv = NULL;

    tree->br_client.bc_iorcb(tree->br_client.bc_rock, &code, node->bn_kv, v, &oldv);

    if (IS_IOR_REP(code)) {
        if (oldv)
            bn_val_free(tree, oldv);
    }

    return node;
}

static struct bonsai_node *
bn_insert_impl(
    struct bonsai_root *        tree,
    struct bonsai_node *        node,
    const struct key_immediate *key_imm,
    const void *                key,
    const struct bonsai_sval *  sval,
    struct bonsai_kv *          parent,
    u32                         flags)
{
    struct bonsai_node *ins;
    s32                 res;

    if (!node) {
        enum bonsai_ior_code code;
        struct bonsai_kv *   head, *prev_span, *next_span;

        node = bn_node_alloc(tree, key_imm, key, sval);
        if (ev(!node))
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

        /* Get the tail end of the tombspans for prev and next nodes. */
        prev_span = node->bn_kv->bkv_prev->bkv_tomb;
        next_span = node->bn_kv->bkv_next->bkv_tomb;

        if (unlikely(prev_span && (prev_span->bkv_flags & BKV_FLAG_TOMB_HEAD)))
            prev_span = prev_span->bkv_tomb;

        if (unlikely(next_span && (next_span->bkv_flags & BKV_FLAG_TOMB_HEAD)))
            next_span = next_span->bkv_tomb;

        if (flags & BN_INSERT_FLAG_TOMB) {
            if (unlikely(prev_span)) {
                head = prev_span->bkv_tomb;
                assert(head->bkv_flags & BKV_FLAG_TOMB_HEAD);
                assert(head->bkv_tomb);

                /* Extend the tombspan to the right */
                if (prev_span != next_span)
                    head->bkv_tomb = node->bn_kv;

                node->bn_kv->bkv_tomb = head;
            } else {
                /* Start a new tomb span */
                head = node->bn_kv;
                head->bkv_flags |= BKV_FLAG_TOMB_HEAD;
                head->bkv_tomb = node->bn_kv;
            }
        } else if (unlikely(prev_span && (prev_span == next_span))) {
            /* This put invalidates a tomb span */
            head = prev_span->bkv_tomb;
            assert(head->bkv_flags & BKV_FLAG_TOMB_HEAD);
            assert(head->bkv_tomb);
            head->bkv_tomb = NULL;
        }

        SET_IOR_INS(code);
        tree->br_client.bc_iorcb(tree->br_client.bc_rock, &code, node->bn_kv, NULL, NULL);

        return node;
    }

    res = key_immediate_cmp(key_imm, &node->bn_key_imm);
    if (res == S32_MIN)
        res = inner_key_cmp(
            key + key_imm->ki_dlen,
            key_imm->ki_klen - key_imm->ki_dlen,
            node->bn_kv->bkv_key + node->bn_key_imm.ki_dlen,
            node->bn_key_imm.ki_klen - node->bn_key_imm.ki_dlen);

    if (res < 0) {
        ins = bn_insert_impl(
            tree, node->bn_left, key_imm, key, sval, node->bn_kv, flags & ~BN_INSERT_FLAG_RIGHT);
        if (ev(!ins))
            return NULL;

        return bn_balance_tree(tree, node, ins, node->bn_right, key_imm, key, B_UPDATE_L);
    }

    if (res > 0) {
        ins = bn_insert_impl(
            tree, node->bn_right, key_imm, key, sval, node->bn_kv, flags | BN_INSERT_FLAG_RIGHT);
        if (ev(!ins))
            return NULL;

        return bn_balance_tree(tree, node, node->bn_left, ins, key_imm, key, B_UPDATE_R);
    }

    assert(res == 0);

    return bn_update(tree, node, sval, flags);
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
    klen = ki->ki_klen;
    skidx = key_immediate_index(ki);

    node = rcu_dereference(tree->br_root);
    mnode = NULL;

    while (node) {
        u32 node_skidx = key_immediate_index(&node->bn_kv->bkv_key_imm);

        res = skidx - node_skidx;
        if (res == 0)
            res = inner_key_cmp(key, klen, node->bn_kv->bkv_key, klen);

        if (res < 0) {
            mnode = node;
            node = rcu_dereference(node->bn_left);
        } else
            node = rcu_dereference(node->bn_right);
    }

    return mnode ? mnode->bn_kv : NULL;
}

static inline struct bonsai_kv *
bn_find_impl(struct bonsai_root *tree, const struct bonsai_skey *skey, enum bonsai_match_type mtype)
{
    struct bonsai_node *        node;
    struct bonsai_node *        mnode;
    const struct key_immediate *ki;
    const void *                key;

    uint klen;
    uint lcp, bounds;
    s32  res;

    ki = &skey->bsk_key_imm;
    key = skey->bsk_key;
    klen = ki->ki_klen;
    lcp = KI_DLEN_MAX;

    /* Once the tree has been finalized we can safely compare the
     * search key to the bounds of the tree and/or leverage the
     * lcp to potentially minimize the amount of work required
     * to search for the key in this tree.
     */
    bounds = atomic_read(&tree->br_bounds);
    if (bounds) {
        struct bonsai_kv *bkv = tree->br_kv.bkv_prev; /* max key */

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
        res = key_immediate_cmp_full(ki, &bkv->bkv_key_imm);
        if (res > 0)
            return (mtype == B_MATCH_LE) ? bkv : NULL;

        bkv = tree->br_kv.bkv_next; /* min key */

        /*
         * If search key < min and there's no more to compare, then
         * return the min key for a GE get and a NULL for EQ get.
         */
        res = key_immediate_cmp_full(ki, &bkv->bkv_key_imm);
        if (res < 0 && res > S32_MIN)
            return (mtype == B_MATCH_GE) ? bkv : NULL;
    }

search:
    key += lcp;
    klen -= lcp;

    node = rcu_dereference(tree->br_root);
    mnode = NULL;

    while (node) {
        res = key_immediate_cmp(ki, &node->bn_key_imm);
        if (unlikely(res == S32_MIN)) {
            assert(node->bn_key_imm.ki_klen >= lcp);

            /* At this point we are assured that both keys'
             * ki_dlen are greater than KI_DLEN_MAX.
             */
            res = inner_key_cmp(
                key, klen, node->bn_kv->bkv_key + lcp, node->bn_key_imm.ki_klen - lcp);
        }

        if (unlikely(res == 0))
            return node->bn_kv;

        if (res < 0) {
            if (unlikely(mtype == B_MATCH_GE))
                mnode = node;
            node = rcu_dereference(node->bn_left);
        } else {
            if (unlikely(mtype == B_MATCH_LE))
                mnode = node;
            node = rcu_dereference(node->bn_right);
        }
    }

    return mnode ? mnode->bn_kv : NULL;
}

static void
_bn_teardown(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *left;
    struct bonsai_node *right;

    if (!node)
        return;

    left = node->bn_left;
    right = node->bn_right;

    if (left)
        _bn_teardown(tree, left);

    if (right)
        _bn_teardown(tree, right);

    bn_node_free(tree, node);
}

static void
_bn_traverse(struct bonsai_node *node)
{
    struct bonsai_node *left;
    struct bonsai_node *right;

    if (!node)
        return;

    left = rcu_dereference(node->bn_left);
    right = rcu_dereference(node->bn_right);

    if (left)
        _bn_traverse(left);

    if (right)
        _bn_traverse(right);
}

static inline void
bn_update_root_node(
    struct bonsai_root *tree,
    struct bonsai_node *oldroot,
    struct bonsai_node *newroot)
{
    assert(oldroot == tree->br_root);
    if (newroot && (oldroot != newroot)) {
        rcu_assign_pointer(tree->br_root, newroot);

        if (likely(oldroot))
            (void)bn_node_free(tree, oldroot);
    }
}

merr_t
bn_insert_or_replace(
    struct bonsai_root *      tree,
    const struct bonsai_skey *skey,
    const struct bonsai_sval *sval,
    bool                      is_tomb)
{
    struct bonsai_node *oldroot;
    struct bonsai_node *newroot;
    u32                 flags;

    oldroot = tree->br_root;
    flags = is_tomb ? BN_INSERT_FLAG_TOMB : 0;

    newroot =
        bn_insert_impl(tree, oldroot, &skey->bsk_key_imm, skey->bsk_key, sval, &tree->br_kv, flags);
    if (ev(!newroot))
        return merr(ENOMEM);

    bn_update_root_node(tree, oldroot, newroot);

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

bool
bn_skiptombs_GE(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv)
{
    struct bonsai_kv *lkv;
    struct bonsai_kv *head;

    assert(kv);

    lkv = bn_find_impl(tree, skey, B_MATCH_GE);
    if (!lkv)
        return false;

    head = lkv->bkv_tomb;
    if (head) {
        struct bonsai_kv *end;

        /* Skip past the contiguous tomb span */
        if (lkv->bkv_flags & BKV_FLAG_TOMB_HEAD) {
            assert(lkv == head || !(head->bkv_flags & BKV_FLAG_TOMB_HEAD));
            end = head;
        } else {
            assert(head->bkv_flags & BKV_FLAG_TOMB_HEAD);
            end = head->bkv_tomb;
        }

        /* The tombspan was invalidated */
        if (!end)
            end = lkv;

        assert(bn_kv_cmp(end, lkv) >= 0);

        if (end->bkv_next == &tree->br_kv)
            return false;

        *kv = end->bkv_next;
        return true;
    }

    *kv = lkv;
    return true;
}

void
bn_destroy(struct bonsai_root *tree)
{
    struct bonsai_node *root;

    if (!tree)
        return;

    root = rcu_dereference(tree->br_root);

    rcu_assign_pointer(tree->br_root, NULL);

    _bn_teardown(tree, root);
    rcu_barrier();

    if (tree->br_client.bc_fn_active != (void *)-1) {
        bn_node_free(tree, NULL);
        rcu_barrier();

        assert(tree->br_client.bc_fn_active == NULL);
        assert(!tree->br_client.bc_fn_pending);
    }

    if (tree->br_client.bc_fv_active != (void *)-1) {
        bn_val_free(tree, NULL);
        rcu_barrier();

        assert(tree->br_client.bc_fv_active == NULL);
        assert(!tree->br_client.bc_fv_pending);
    }

    bn_free(tree, tree);
}

void
bn_traverse(struct bonsai_root *tree)
{
    struct bonsai_node *root;

    root = rcu_dereference(tree->br_root);

    _bn_traverse(root);
}

void
bn_reset(struct bonsai_root *tree)
{
    struct bonsai_client *client;

    client = &tree->br_client;

    rcu_assign_pointer(tree->br_root, NULL);

    tree->br_kv.bkv_prev = &tree->br_kv;
    tree->br_kv.bkv_next = &tree->br_kv;
    tree->br_kv.bkv_tomb = NULL;
    tree->br_kv.bkv_flags = 0;

    atomic_set(&tree->br_bounds, 0);

    client->bc_slab_cur = NULL;
    client->bc_slab_end = NULL;

    client->bc_fv_active = NULL;
    client->bc_fv_pending = NULL;
    client->bc_fn_active = NULL;
    client->bc_fn_pending = NULL;

    /* Disable value freeing when using the cheap allocator.
     */
    if (client->bc_allocator) {
        client->bc_fv_active = (void *)(-1);
        client->bc_fn_active = (void *)(-1);
    }

#ifdef BONSAI_TREE_DEBUG_ALLOC
    client->bc_add = 0;
    client->bc_dup = 0;
    client->bc_dupdel = 0;
    client->bc_del = 0;
#endif
}

merr_t
bn_create(
    struct cheap *       cheap,
    unsigned long        slabsz,
    bonsai_ior_cb        cb,
    void *               rock,
    struct bonsai_root **tree)
{
    struct bonsai_root *r;

    if (ev(!cb || !tree))
        return merr(EINVAL);

    r = bn_alloc_impl(cheap, sizeof(*r));
    if (ev(!r))
        return merr(ENOMEM);

    memset(r, 0, sizeof(*r));

    r->br_client.bc_iorcb = cb;
    r->br_client.bc_rock = rock;
    r->br_client.bc_allocator = cheap;
    r->br_client.bc_slab_sz = slabsz;

    bn_reset(r);

    *tree = r;

    return 0;
}

void
bn_finalize(struct bonsai_root *tree)
{
    const struct bonsai_kv *kmin, *kmax;
    uint                    lcp, set_lcp = 0;

    kmin = tree->br_kv.bkv_next;
    kmax = tree->br_kv.bkv_prev;

    /* If all the keys in the tree are sufficiently long then we
     * check to see if they have a common prefix.  If so, we can
     * leverage the longest common prefix to reduce the amount
     * of work required to find a key in TreeBB_Find().
     */
    if (kmin != kmax) {
        lcp = min_t(uint, kmin->bkv_key_imm.ki_klen, kmax->bkv_key_imm.ki_klen);

        if (lcp > KI_DLEN_MAX &&
            key_immediate_index(&kmin->bkv_key_imm) == key_immediate_index(&kmax->bkv_key_imm)) {

            lcp = memlcpq(kmin->bkv_key, kmax->bkv_key, lcp);
            if (lcp > KI_DLEN_MAX) {
                assert(key_immediate_cmp(&kmin->bkv_key_imm, &kmax->bkv_key_imm) == S32_MIN);
                set_lcp = lcp;
            }
        }

        /* Indicate that the bounds have been established and the lcp to use. */
        atomic_set(&tree->br_bounds, set_lcp + 1);
    }
}
