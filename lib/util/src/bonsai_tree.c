/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>

#include "bonsai_tree_pvt.h"

#define BN_INSERT_FLAG_RIGHT 0x01u
#define BN_INSERT_FLAG_TOMB  0x02u

static struct bonsai_node *
bn_ior_replace(
    struct bonsai_root *      tree,
    struct bonsai_node *      node,
    const struct bonsai_sval *sval,
    u32                       flags)
{
    struct bonsai_val *  v;
    struct bonsai_val *  oldv;
    enum bonsai_ior_code code;

    /* Invalidate the tombspan, if any. */
    if (HSE_UNLIKELY(!(flags & BN_INSERT_FLAG_TOMB) && node->bn_kv->bkv_tomb)) {
        node->bn_kv->bkv_tomb->bkv_tomb = NULL;
        node->bn_kv->bkv_tomb = NULL;
    }

    v = bn_val_alloc(tree, sval);
    if (!v)
        return NULL;

    SET_IOR_REPORADD(code);
    oldv = NULL;

    tree->br_client.bc_iorcb(tree->br_client.bc_rock, &code, node->bn_kv, v, &oldv);

    return node;
}

static struct bonsai_node *
bn_ior_insert(
    struct bonsai_root *        tree,
    const struct key_immediate *key_imm,
    const void *                key,
    const struct bonsai_sval *  sval,
    struct bonsai_kv *          parent,
    u32                         flags)
{
    struct bonsai_kv *   head, *prev_span, *next_span;
    struct bonsai_node * node;
    enum bonsai_ior_code code;

    node = bn_node_alloc(tree, key_imm, key, sval);
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

    /* Get the tail end of the tombspans for prev and next nodes. */
    prev_span = node->bn_kv->bkv_prev->bkv_tomb;
    next_span = node->bn_kv->bkv_next->bkv_tomb;

    if (HSE_UNLIKELY(prev_span && (prev_span->bkv_flags & BKV_FLAG_TOMB_HEAD)))
        prev_span = prev_span->bkv_tomb;

    if (HSE_UNLIKELY(next_span && (next_span->bkv_flags & BKV_FLAG_TOMB_HEAD)))
        next_span = next_span->bkv_tomb;

    if (flags & BN_INSERT_FLAG_TOMB) {
        if (HSE_UNLIKELY(prev_span)) {
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
    } else if (HSE_UNLIKELY(prev_span && (prev_span == next_span))) {
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

/* For efficiency, bn_ior_impl() uses the least-significant bit
 * of the bonsai node pointer to remember which way it went when
 * searching for the insertion point.
 */
#define BN_IOR_RIGHT ((uintptr_t)BN_INSERT_FLAG_RIGHT)
#define BN_IOR_MASK  ((uintptr_t)(sizeof(uintptr_t) - 1))

_Static_assert(
    BN_IOR_RIGHT > 0 && BN_IOR_RIGHT < BN_IOR_MASK,
    "bn_ior_impl() requires BN_INSERT_FLAG_RIGHT to be 1 or 2");

static struct bonsai_node *
bn_ior_impl(
    struct bonsai_root *        tree,
    struct bonsai_node *        node,
    const struct key_immediate *key_imm,
    const void *                key,
    const struct bonsai_sval *  sval,
    struct bonsai_kv *          parent,
    u32                         flags)
{
    struct bonsai_node *prev;
    int                 n = 0;
    s32                 res;

    /* Find the position to insert or node to replace, keeping track
     * of all nodes visited and which way (left or right) we went...
     */
    while (node) {
        res = key_full_cmp(key_imm, key, &node->bn_key_imm, node->bn_kv->bkv_key);

        if (HSE_UNLIKELY(res == 0))
            break;

        if (res < 0) {
            tree->br_stack[n++] = (uintptr_t)node;
            node = node->bn_left;
        } else {
            tree->br_stack[n++] = (uintptr_t)node | BN_IOR_RIGHT;
            node = node->bn_right;
        }

        __builtin_prefetch(node, 0, 2);

        if (n >= NELEM(tree->br_stack))
            return NULL; /* should never happen */
    }

    if (n > 0) {
        flags &= ~BN_INSERT_FLAG_RIGHT;
        flags |= (tree->br_stack[n - 1] & BN_IOR_MASK);
        prev = (void *)(tree->br_stack[n - 1] & ~BN_IOR_MASK);
        parent = prev->bn_kv;
    }

    if (node)
        node = bn_ior_replace(tree, node, sval, flags);
    else
        node = bn_ior_insert(tree, key_imm, key, sval, parent, flags);

    if (!node)
        return NULL;

    /* Failure up to this point is safe in that the tree will not have been
     * modified.  It's not clear, however, if failure during rebalancing
     * could yield a corrupted tree.  To be safe, the caller must ensure
     * that there is sufficient memory for about (maxdepth * 3) nodes.
     */
    while (node && n-- > 0) {
        bool right;

        right = (void *)(tree->br_stack[n] & BN_IOR_RIGHT);
        prev = (void *)(tree->br_stack[n] & ~BN_IOR_MASK);

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
    if (bounds) {
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
            if (HSE_UNLIKELY(mtype == B_MATCH_GE))
                mnode = node;
            node = rcu_dereference(node->bn_left);
        } else {
            if (HSE_UNLIKELY(mtype == B_MATCH_LE))
                mnode = node;
            node = rcu_dereference(node->bn_right);
        }

        __builtin_prefetch(node, 0, 2);
    }

    return mnode ? mnode->bn_kv : NULL;
}

static inline void
bn_update_root_node(
    struct bonsai_root *tree,
    struct bonsai_node *oldroot,
    struct bonsai_node *newroot)
{
    assert(oldroot == tree->br_root);

    if (newroot && (oldroot != newroot))
        rcu_assign_pointer(tree->br_root, newroot);
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
        bn_ior_impl(tree, oldroot, &skey->bsk_key_imm, skey->bsk_key, sval, &tree->br_kv, flags);
    if (!newroot)
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
}

merr_t
bn_create(
    struct cheap *       cheap,
    size_t               slabsz,
    bonsai_ior_cb        cb,
    void *               rock,
    struct bonsai_root **tree)
{
    struct bonsai_root *r;

    if (ev(!cheap || !cb || !tree))
        return merr(EINVAL);

    r = cheap_memalign(cheap, __alignof(*r), sizeof(*r));
    if (ev(!r))
        return merr(ENOMEM);

    memset(r, 0, sizeof(*r));

    r->br_client.bc_iorcb = cb;
    r->br_client.bc_rock = rock;
    r->br_client.bc_cheap = cheap;
    r->br_client.bc_slab_sz = slabsz;

    bn_reset(r);

    *tree = r;

    return 0;
}

void
bn_destroy(struct bonsai_root *tree)
{
    if (tree)
        rcu_assign_pointer(tree->br_root, NULL);
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
     * of work required to find a key in TreeBB_Find().
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

__attribute__((__cold__)) static void
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

__attribute__((__cold__)) void
bn_traverse(struct bonsai_root *tree)
{
    struct bonsai_node *root;

    root = rcu_dereference(tree->br_root);

    _bn_traverse(root);
}
