/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/util/log2.h>
#include <hse/logging/logging.h>

#include "bonsai_tree_pvt.h"

#define BN_INSERT_FLAG_RIGHT    (0x01u)

int
bn_summary(struct bonsai_root *tree, char *buf, size_t bufsz)
{
    ulong rnodec = 0, nodec = 0;
    int slabc = 0, n = 0, i;
    char sibuf[256];

    if (!tree)
        return 0;

    for (i = 0; i < NELEM(tree->br_slabinfov); ++i) {
        struct bonsai_slabinfo *slabinfo = tree->br_slabinfov + i;
        struct bonsai_slab *slab;

        slab = slabinfo->bsi_slab;
        if (!slab)
            return 0;

        slabinfo->bsi_rnodec += slab->bs_rnodec;
        slabinfo->bsi_nodec += slab->bs_nodec;

        if (slabinfo->bsi_nodec > 0 && n < sizeof(sibuf)) {
            n += snprintf(sibuf + n, sizeof(sibuf) - n, "  %u,%lu,%lu,%u",
                          i, slabinfo->bsi_nodec, slabinfo->bsi_rnodec,
                          slabinfo->bsi_slabc);
        }

        rnodec += slabinfo->bsi_rnodec;
        nodec += slabinfo->bsi_nodec;
        slabc += slabinfo->bsi_slabc;
    }

    if (nodec < 1)
        return 0;

    return snprintf(
        buf, bufsz, "%2d %2d  keys %lu  vals %lu  nodes %lu,%lu,%u  %.2lf  (%u %lu %3lu) %s",
        tree->br_height, atomic_read(&tree->br_bounds),
        tree->br_key_alloc, tree->br_key_alloc + tree->br_val_alloc,
        nodec, rnodec, slabc,
        (double)(nodec + rnodec) / tree->br_key_alloc,
        atomic_read(&tree->br_gc_rcugen_done),
        (tree->br_gc_latsum_gp / 1000000) / atomic_read(&tree->br_gc_rcugen_done),
        (tree->br_gc_latsum_gc / 1000) / atomic_read(&tree->br_gc_rcugen_done),
        sibuf);
}

static struct bonsai_node *
bn_ior_replace(
    struct bonsai_root *      tree,
    const struct bonsai_skey *skey,
    struct bonsai_sval       *sval,
    struct bonsai_node       *node)
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
    if (oldv)
        bn_val_rcufree(node->bn_kv, oldv);

    sval->bsv_seqnoref = v->bv_seqnoref;

    return tree->br_root;
}

static struct bonsai_node *
bn_ior_insert(
    struct bonsai_root         *tree,
    const struct bonsai_skey   *skey,
    struct bonsai_sval         *sval,
    struct bonsai_kv           *kvlist,
    uint32_t                    flags)
{
    struct bonsai_node *node;
    struct bonsai_val  *val;
    enum bonsai_ior_code code;

    node = bn_kvnode_alloc(tree, skey, sval);
    if (!node)
        return NULL;

    if (flags & BN_INSERT_FLAG_RIGHT) {
        node->bn_kv->bkv_next = kvlist->bkv_next;
        node->bn_kv->bkv_prev = kvlist;
    } else {
        node->bn_kv->bkv_next = kvlist;
        node->bn_kv->bkv_prev = kvlist->bkv_prev;
    }

    rcu_assign_pointer(node->bn_kv->bkv_next->bkv_prev, node->bn_kv);
    rcu_assign_pointer(node->bn_kv->bkv_prev->bkv_next, node->bn_kv);

    SET_IOR_INS(code);
    tree->br_ior_cb(tree->br_ior_cbarg, &code, node->bn_kv, NULL, NULL, tree->br_height);

    val = rcu_dereference(node->bn_kv->bkv_values);
    sval->bsv_seqnoref = val->bv_seqnoref;

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
    const struct bonsai_skey   *skey,
    struct bonsai_sval         *sval)
{
    const struct key_immediate *key_imm;
    struct bonsai_node *node;
    struct bonsai_kv *kvlist;
    uintptr_t stack[48];
    const void *key;
    uint32_t flags;
    int n = 0;
    int32_t res;

    key_imm = &skey->bsk_key_imm;
    key = skey->bsk_key;
    node = tree->br_root;

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

    assert(n < NELEM(stack)); /* should never ever fail */

    if (node)
        return bn_ior_replace(tree, skey, sval, node);

    if (n > 0) {
        struct bonsai_node *parent;

        flags = (stack[n - 1] & BN_IOR_MASK);
        parent = (void *)(stack[n - 1] & ~BN_IOR_MASK);
        kvlist = parent->bn_kv;
    } else {
        kvlist = &tree->br_kv;
        flags = 0;
    }

    node = bn_ior_insert(tree, skey, sval, kvlist, flags);
    if (!node)
        return NULL;

    /* Failure up to this point is safe in that the tree will not have been
     * modified.  However, failure to allocate a node during rebalancing does
     * leave the tree corrupted.  We now have in place a reserved slab that
     * should be sufficiently large to complete any rebalance operation,
     * after which we disallow subsequent inserts.
     */
    while (n-- > 0) {
        struct bonsai_node *parent;
        bool right;

        right = (stack[n] & BN_IOR_RIGHT);
        parent = (void *)(stack[n] & ~BN_IOR_MASK);

        assert(node->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);
        assert(parent->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);

        if (right)
            node = bn_balance(tree, parent, parent->bn_left, node);
        else
            node = bn_balance(tree, parent, node, parent->bn_right);
    }

    if (tree->br_height != node->bn_height)
        tree->br_height = node->bn_height;

    return node;
}

static merr_t
bn_delete_impl(
    struct bonsai_root       *tree,
    const struct bonsai_skey *skey,
    struct bonsai_node      **newrootp)
{
    const struct key_immediate *key_imm;
    struct bonsai_node *dnode, *dnparentdup;
    struct bonsai_node *node, *parent;
    uintptr_t stack[48];
    const void *key;
    bool right;
    int n = 0;
    int32_t res;

    key_imm = &skey->bsk_key_imm;
    key = skey->bsk_key;
    dnode = tree->br_root;

    /* Find the node to delete, keeping track of all nodes visited and which way
     * we went (i.e., left or right).
     */
    while (dnode) {
        res = key_full_cmp(key_imm, key, &dnode->bn_key_imm, dnode->bn_kv->bkv_key);

        if (HSE_UNLIKELY(res == 0))
            break;

        if (res < 0) {
            stack[n++] = (uintptr_t)dnode;
            dnode = dnode->bn_left;
        } else {
            stack[n++] = (uintptr_t)dnode | BN_IOR_RIGHT;
            dnode = dnode->bn_right;
        }
    }

    assert(n < NELEM(stack)); /* should never ever fail */

    if (!dnode)
        return merr(ENOENT);

    /* Make the deleted node and its kv node available for garbage collection
     * in the next rcu epoch.
     */
    bn_node_rcufree(tree, dnode);
    bn_kv_rcufree(tree, dnode->bn_kv);

    /* Remove the deleted node's kv node from the list of sorted keys.  Outside
     * callers who wish to traverse this list must do so under the rcu read
     * lock (unless the tree has been finalized).
     */
    rcu_assign_pointer(dnode->bn_kv->bkv_next->bkv_prev, dnode->bn_kv->bkv_prev);
    rcu_assign_pointer(dnode->bn_kv->bkv_prev->bkv_next, dnode->bn_kv->bkv_next);

    /* Half the nodes in the tree are either leaves or have only one child,
     * so check for them first...
     */
    if (!dnode->bn_left || !dnode->bn_right) {
        struct bonsai_node *dnchild = dnode->bn_left ?: dnode->bn_right;

        /* At this point the node to be deleted has at most one child.
         * If the deleted node is at the root of the tree then its
         * child becomes the new root.
         */
        if (n == 0) {
            tree->br_height = bn_height_get(dnchild);
            *newrootp = dnchild;

            return 0;
        }

        /* Otherwise dup the deleted node's parent so as to eliminate the
         * deleted node and preserve the deleted node's left or right child.
         * As an optimization, if dnode has no children then we can simply
         * update it in place and avoid having to duplicate its parent.
         */
        parent = (void *)(stack[--n] & ~BN_IOR_MASK);
        right = (stack[n] & BN_IOR_RIGHT);

        if (right) {
            if (dnchild) {
                dnparentdup = bn_node_dup_ext(tree, parent, parent->bn_left, dnchild);
                bn_node_rcufree(tree, parent);
            } else {
                rcu_assign_pointer(parent->bn_right, NULL);
                dnparentdup = parent;
            }
        } else {
            if (dnchild) {
                dnparentdup = bn_node_dup_ext(tree, parent, dnchild, parent->bn_right);
                bn_node_rcufree(tree, parent);
            } else {
                rcu_assign_pointer(parent->bn_left, NULL);
                dnparentdup = parent;
            }
        }
    }
    else {
        struct bonsai_node *snode = dnode->bn_right;

        /* To delete an interior node we must replace it with its successor node,
         * which should be a leaf down the left side of this branch (but sometimes
         * has a right child).  Here we push the dnode on the stack to use as a
         * sentinel in the loop to rebuild the path to the deleted node.
         */
        stack[n++] = (uintptr_t)dnode;

        while (snode->bn_left) {
            stack[n++] = (uintptr_t)snode;
            snode = snode->bn_left;
        }

        assert(n < NELEM(stack));

        node = snode->bn_right;

        /* Build a new path from the successor back to but not including
         * the deleted node, eliminating the successor node but pulling
         * up its right child.
         *
         * We don't call bn_balance() here because it might update
         * in place prematurely leaving the tree in a state where
         * the successor node is temporily invisible.
         */
        while (dnode != ((parent = (void *)stack[--n]))) {
            node = bn_node_dup_ext(tree, parent, node, parent->bn_right);
            bn_height_update(node);

            bn_node_rcufree(tree, parent);
        }

        /* Dup the successor node to replace (and hence eliminate) the
         * deleted node from the new path.
         */
        dnparentdup = bn_node_dup_ext(tree, snode, dnode->bn_left, node);
    }

    assert(dnparentdup);

    bn_height_update(dnparentdup);
    node = dnparentdup;

    while (n-- > 0) {
        right = (stack[n] & BN_IOR_RIGHT);
        parent = (void *)(stack[n] & ~BN_IOR_MASK);

        assert(node->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);
        assert(parent->bn_rcugen == HSE_BN_RCUGEN_ACTIVE);

        if (right)
            node = bn_balance(tree, parent, parent->bn_left, node);
        else
            node = bn_balance(tree, parent, node, parent->bn_right);
    }

    tree->br_height = node->bn_height;

    *newrootp = node;

    return 0;
}

static inline struct bonsai_kv *
bn_find_next_pfx(struct bonsai_root *tree, const struct bonsai_skey *skey, enum bonsai_match_type mtype)
{
    struct bonsai_node *        node;
    struct bonsai_node *        node_gt, *node_lt;
    const struct key_immediate *ki;
    const void *                key;

    uint klen;
    int32_t res;
    uint32_t  skidx;

    /* [HSE_REVISIT] Optimize using lcp */

    ki = &skey->bsk_key_imm;
    key = skey->bsk_key;
    klen = key_imm_klen(ki);
    skidx = key_immediate_index(ki);

    node = rcu_dereference(tree->br_root);
    node_gt = node_lt = NULL;

    while (node) {
        uint32_t node_skidx = key_immediate_index(&node->bn_kv->bkv_key_imm);

        res = skidx - node_skidx;
        if (res == 0)
            res = key_inner_cmp(key, klen, node->bn_kv->bkv_key, klen);

        if (res < 0) {
            node_gt = node;
            node = rcu_dereference(node->bn_left);
        } else {
            node_lt = node;
            node = rcu_dereference(node->bn_right);
        }
    }

    if (mtype == B_MATCH_GT)
        return node_gt ? node_gt->bn_kv : NULL;

    if (mtype == B_MATCH_LT)
        return node_lt ? node_lt->bn_kv : NULL;

    return NULL;
}

static inline struct bonsai_kv *
bn_find_impl(struct bonsai_root *tree, const struct bonsai_skey *skey, enum bonsai_match_type mtype)
{
    struct bonsai_node *node, *node_le, *node_ge;
    const struct key_immediate *ki;
    const void *key;
    uint klen;
    int  bounds;
    int32_t res;

    ki = &skey->bsk_key_imm;
    key = skey->bsk_key;
    klen = key_imm_klen(ki);

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
        uint lcp;

        /* br_bounds is set to 1 + the lcp to use. */
        lcp = min_t(uint, klen, bounds - 1);

        if (lcp > KI_DLEN_MAX &&
            key_immediate_index(ki) == key_immediate_index(&bkv->bkv_key_imm)) {

            lcp = memlcpq(key, bkv->bkv_key, lcp);
            if (lcp > KI_DLEN_MAX) {
                assert(key_immediate_cmp(ki, &bkv->bkv_key_imm) == INT32_MIN);
                goto search;
            }
        }

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
        if (res < 0 && res > INT32_MIN)
            return (mtype == B_MATCH_GE) ? bkv : NULL;
    }

search:
    node = rcu_dereference(tree->br_root);
    node_le = node_ge = NULL;

    while (node) {
        res = key_immediate_cmp(ki, &node->bn_key_imm);

        if (HSE_UNLIKELY(res == INT32_MIN)) {

            /* At this point we are assured that both keys'
             * ki_dlen are greater than KI_DLEN_MAX.
             */
            res = key_inner_cmp(
                key, klen, node->bn_kv->bkv_key, key_imm_klen(&node->bn_key_imm));
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
     struct bonsai_sval      *sval)
{
    struct bonsai_node *newroot;

    /* Reject attempts to modify the tree if it has been finalized
     * (bounds > 0) or is out of memory (bounds < 0).
     */
    if (atomic_read(&tree->br_bounds))
        return merr(ENOMEM);

    newroot = bn_ior_impl(tree, skey, sval);
    if (!newroot)
        return merr(ENOMEM);

    if (newroot != tree->br_root)
        rcu_assign_pointer(tree->br_root, newroot);

    return 0;
}

merr_t
bn_delete(
    struct bonsai_root       *tree,
    const struct bonsai_skey *skey)
{
    struct bonsai_node *newroot;
    merr_t err;

    /* Reject attempts to modify the tree if it has been finalized
     * (bounds > 0) or is out of memory (bounds < 0).
     */
    if (atomic_read(&tree->br_bounds))
        return merr(ENOMEM);

    err = bn_delete_impl(tree, skey, &newroot);
    if (err)
        return err;

    if (newroot != tree->br_root)
        rcu_assign_pointer(tree->br_root, newroot);

    /* Amortize key-garbage removal over multiple delete calls.  br_rfkeys
     * is the head of a list of lists, where bkv_next points to the next
     * list and bkv_free points to the next key in a given list.
     */
    if (tree->br_rfkeys) {
        struct bonsai_kv *kvlist;

        spin_lock(&tree->br_gc_lock);
        kvlist = tree->br_rfkeys;
        if (kvlist)
            tree->br_rfkeys = kvlist->bkv_next;
        spin_unlock(&tree->br_gc_lock);

        bn_kv_free(kvlist);
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

    lkv = bn_find_next_pfx(tree, skey, B_MATCH_GT);
    if (lkv) {
        *kv = lkv;
        return true;
    }

    return false;
}

bool
bn_find_pfx_LT(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv)
{
    struct bonsai_kv *lkv;

    assert(kv);

    lkv = bn_find_next_pfx(tree, skey, B_MATCH_LT);
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
                assert(key_immediate_cmp(&kmin->bkv_key_imm, &kmax->bkv_key_imm) == INT32_MIN);
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
    struct bonsai_slab *slab, *next;
    struct bonsai_kv *kv;

    if (!tree || tree->br_cheap || !tree->br_rootslab)
        return;

    bn_kv_free(tree->br_vfkeys);

    while (( kv = tree->br_rfkeys )) {
        tree->br_rfkeys = kv->bkv_next;
        bn_kv_free(kv);
    }

    while (( kv = tree->br_gc_vfkeys )) {
        tree->br_gc_vfkeys = kv->bkv_next;
        bn_kv_free(kv);
    }

    tree->br_kv.bkv_prev->bkv_next = NULL;

    while (( kv = tree->br_kv.bkv_next )) {
        tree->br_kv.bkv_next = kv->bkv_next;
        bn_kv_free(kv);
    }

    /* All slabs allocated must be on one of the wait, hold, or free
     * queues.  Freeing all the slabs destroys all the nodes in the
     * tree without having to actually walk the tree.
     */
    while (( slab = tree->br_gc_waitq )) {
        tree->br_gc_waitq = slab->bs_next;
        bn_slab_free(slab);
    }

    assert(!tree->br_gc_readyq);

    list_for_each_entry_safe(slab, next, &tree->br_gc_holdq, bs_entry)
        bn_slab_free(slab);

    for (int i = 0; i < NELEM(tree->br_slabinfov); ++i) {
        struct bonsai_slabinfo *slabinfo = tree->br_slabinfov + i;

        list_for_each_entry_safe(slab, next, &slabinfo->bsi_freeq, bs_entry)
            bn_slab_free(slab);

        bn_slab_free(slabinfo->bsi_slab);
    }
}

void
bn_reset(struct bonsai_root *tree)
{
#ifdef HSE_BUILD_DEBUG
    static thread_local uint bn_summary_calls_tls;
    char buf[384];
#endif

    assert(tree->br_magic == (uint)(uintptr_t)tree);

    /* Wait for all rcu callbacks to complete.
     */
    while (rcu_dereference(tree->br_gc_readyq))
        rcu_barrier();

#ifdef HSE_BUILD_DEBUG
    if ((tree->br_oomslab || bn_summary_calls_tls++ % 8 == 0) &&
        bn_summary(tree, buf, sizeof(buf)) > 0) {

        log_debug("%s", buf);
    }
#endif

    bn_reset_impl(tree);

    memset(&tree->br_height, 0, sizeof(*tree) - offsetof(struct bonsai_root, br_height));

    tree->br_kv.bkv_prev = &tree->br_kv;
    tree->br_kv.bkv_next = &tree->br_kv;

    spin_lock_init(&tree->br_gc_lock);
    atomic_set(&tree->br_gc_rcugen_start, 1);
    atomic_set(&tree->br_gc_rcugen_done, 1);
    INIT_LIST_HEAD(&tree->br_gc_holdq);

    for (size_t i = 0; i < NELEM(tree->br_slabinfov); ++i) {
        struct bonsai_slabinfo *slabinfo = tree->br_slabinfov + i;

        spin_lock_init(&slabinfo->bsi_lock);
        INIT_LIST_HEAD(&slabinfo->bsi_freeq);

        /* All slabinfo records must have a valid slab at all times.
         */
        slabinfo->bsi_slab0 = tree->br_slabbase + HSE_BT_SLABSZ * i;
        bn_slab_init(slabinfo->bsi_slab0, slabinfo, false);
    }

    tree->br_rootslab = tree->br_slabinfov + NELEM(tree->br_slabinfov) - 2;
    tree->br_oomslab = NULL;

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
        r = cheap_memalign(cheap, __alignof__(*r), sz);
    } else {
        r = aligned_alloc(__alignof__(*r), sz);
    }

    if (!r)
        return merr(ENOMEM);

    memset(r, 0, sizeof(*r));
    r->br_cheap = cheap;
    r->br_ior_cb = cb;
    r->br_ior_cbarg = cbarg;
    r->br_slabbase = (r + 1);
    r->br_slabbase = PTR_ALIGN(r->br_slabbase, PAGE_SIZE);
    r->br_magic = (uint)(uintptr_t)r;

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

    assert(tree->br_magic == (uint)(uintptr_t)tree);
    tree->br_magic = 0xbadcafe3;

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
