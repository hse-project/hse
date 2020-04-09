/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>

#include "bonsai_tree_pvt.h"

void *
bn_alloc_impl(struct cheap *allocator, size_t sz)
{
    if (allocator)
        return cheap_malloc(allocator, sz);

    return malloc(sz);
}

void *
bn_alloc(struct bonsai_root *tree, size_t sz)
{
    return bn_alloc_impl(tree->br_client.bc_allocator, sz);
}

static inline void
bn_free_impl(struct bonsai_client *client, void *ptr)
{
    if (!client->bc_allocator)
        free(ptr);
}

static inline void
bn_freen_impl(struct bonsai_client *client, void *node)
{
    bn_free_impl(client, node);

#ifdef BONSAI_TREE_DEBUG_ALLOC
    BONSAI_RCU_ATOMIC_INC(&client->bc_del);
#endif
}

void
bn_free(struct bonsai_root *tree, void *ptr)
{
    bn_free_impl(&tree->br_client, ptr);
}

static inline void *
bn_node_alloc_impl(struct bonsai_root *tree)
{
    struct bonsai_client *client;

    void *ptr;

    client = &tree->br_client;
    ptr = NULL;

    if (client->bc_allocator) {
        void *mem;

        assert(client->bc_allocator);

        if (client->bc_slab_cur >= client->bc_slab_end) {
            unsigned long slabsz;

            slabsz = client->bc_slab_sz;

            mem = cheap_memalign(client->bc_allocator, 64, slabsz);
            if (ev(!mem))
                goto exit;

            client->bc_slab_cur = mem;
            client->bc_slab_end = client->bc_slab_cur + (slabsz / sizeof(struct bonsai_node));
        }

        ptr = client->bc_slab_cur++;
    } else {
        ptr = malloc(sizeof(struct bonsai_node));
    }

exit:
#ifdef BONSAI_TREE_DEBUG_ALLOC
    if (ptr)
        BONSAI_RCU_ATOMIC_INC(&client->bc_add);
#endif

    return ptr;
}

static void
bn_node_free_impl(struct rcu_head *rh)
{
    struct bonsai_client *client;
    struct bonsai_node *  node;
    void *                next;

    client = caa_container_of(rh, struct bonsai_client, bc_fn_rcu);

    node = client->bc_fn_active;
    while (node) {
        if (node->bn_flags & BN_KVFREEOK) {
            struct bonsai_val *val;
            struct bonsai_kv * kv;

            kv = node->bn_kv;
            assert(kv);
            assert(kv->bkv_refcnt == 0);

            val = kv->bkv_values;
            while (val) {
                next = val->bv_next;
                bn_free_impl(client, val);
                val = next;
            }

            bn_free_impl(client, kv);
        }

        next = node->bn_free;
        bn_freen_impl(client, node);
#ifdef BONSAI_TREE_DEBUG_ALLOC
        BONSAI_RCU_ATOMIC_INC(&client->bc_dupdel);
#endif
        node = next;
    }

    /* Barrier to prevent reordering by the compiler.
     */
    rcu_assign_pointer(client->bc_fn_active, NULL);
}

/**
 * bn_node_free - Free a node after the current grace period
 * @tree: root of bonsai tree
 * @node: the node to free
 *
 * This function may only be called by an updater (i.e., not a reader)
 * who either holds an exclusive lock to prevent concurrent update or
 * is single threaded.
 *
 * Multiple nodes can reference the same kv, and so we set the KVFREEOK
 * flag only if the kv reference count goes to zero.  Note that
 * bn_node_free_impl() cannot check the reference count because all nodes
 * that reference the kv could all be freed together, and by the time
 * bn_node_free_impl() runs they would all see the refcnt as zero.  Hence
 * the per-node flag.
 */
void
bn_node_free(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_client *client;

    client = &tree->br_client;

    if (node) {
        assert(node->bn_kv->bkv_refcnt > 0);

        if (node->bn_kv && --node->bn_kv->bkv_refcnt == 0)
            node->bn_flags |= BN_KVFREEOK;

        node->bn_free = client->bc_fn_pending;
        client->bc_fn_pending = node;
    }

    if (!client->bc_fn_active && client->bc_fn_pending) {
        rcu_assign_pointer(client->bc_fn_active, client->bc_fn_pending);
        client->bc_fn_pending = NULL;
        call_rcu(&client->bc_fn_rcu, bn_node_free_impl);
    }
}

static void
bn_val_free_impl(struct rcu_head *rh)
{
    struct bonsai_client *client;
    struct bonsai_val *   val, *next;

    client = caa_container_of(rh, struct bonsai_client, bc_fv_rcu);

    val = client->bc_fv_active;
    while (val) {
        next = val->bv_free;
        bn_free_impl(client, val);
        val = next;
    }

    /* Barrier to prevent reordering by the compiler.
     */
    rcu_assign_pointer(client->bc_fv_active, NULL);
}

/**
 * bn_val_free - Free a bonsai_val after the current grace period
 * @tree: root of the tree
 * @val:  the bonsai_val to free
 *
 * This function may only be called by an updater (i.e., not a reader)
 * who either holds an exclusive lock to prevent concurrent update or
 * is single threaded.
 */
void
bn_val_free(struct bonsai_root *tree, struct bonsai_val *val)
{
    struct bonsai_client *client;

    client = &tree->br_client;

    if (val) {
        val->bv_free = client->bc_fv_pending;
        client->bc_fv_pending = val;
    }

    if (!client->bc_fv_active && client->bc_fv_pending) {
        rcu_assign_pointer(client->bc_fv_active, client->bc_fv_pending);
        client->bc_fv_pending = NULL;
        call_rcu(&client->bc_fv_rcu, bn_val_free_impl);
    }
}

struct bonsai_val *
bn_val_alloc(struct bonsai_root *tree, const struct bonsai_sval *sval)
{
    struct bonsai_val *v;
    size_t             sz;
    u32                vlen;

    vlen = sval->bsv_vlen;
    sz = sizeof(*v) + vlen;

    v = bn_alloc(tree, sz);
    if (ev(!v))
        return NULL;

    v->bv_next = NULL;
    v->bv_free = NULL;
    v->bv_seqnoref = sval->bsv_seqnoref;
    v->bv_flags = 0;
    v->bv_vlen = vlen;
    v->bv_valuep = sval->bsv_val;
    v->bv_rock = NULL;
    atomic64_set(&v->bv_priv, 0);

    if (vlen > 0)
        memcpy(v->bv_value, sval->bsv_val, vlen);

    return v;
}

static inline merr_t
bn_kv_init(
    struct bonsai_root *        tree,
    const struct key_immediate *key_imm,
    const void *                key,
    const struct bonsai_sval *  sval,
    struct bonsai_kv **         kv_out)
{
    struct bonsai_val *v;
    struct bonsai_kv * kv;

    size_t sz;
    int    i;

    sz = sizeof(*kv) + key_imm->ki_klen;

    kv = bn_alloc(tree, sz);
    if (ev(!kv))
        return merr(ENOMEM);

    kv->bkv_next = NULL;
    kv->bkv_prev = NULL;
    kv->bkv_tomb = NULL;

    for (i = 0; i < BONSAI_MUT_LISTC; i++) {
        INIT_S_LIST_HEAD(&kv->bkv_mnext[i]);
        INIT_S_LIST_HEAD(&kv->bkv_txmnext[i]);
    }
    INIT_S_LIST_HEAD(&kv->bkv_txpend);

    kv->bkv_refcnt = 0;
    kv->bkv_flags = 0;
    kv->bkv_key_imm = *key_imm;
    memcpy(kv->bkv_key, key, key_imm->ki_klen);

    v = bn_val_alloc(tree, sval);
    if (ev(!v))
        return merr(ENOMEM);

    kv->bkv_values = v;

    *kv_out = kv;

    return 0;
}

static struct bonsai_node *
bn_node_make(
    struct bonsai_root *        tree,
    struct bonsai_node *        left,
    struct bonsai_node *        right,
    struct bonsai_kv *          kv,
    const struct key_immediate *ki,
    u16                         flags)
{
    struct bonsai_node *node;

    node = bn_node_alloc_impl(tree);
    if (ev(!node))
        return NULL;

    node->bn_left = left;
    node->bn_right = right;
    node->bn_kv = kv;
    node->bn_flags = flags;
    node->bn_height = bn_height_max(bn_height_get(left), bn_height_get(right));

    if (ki)
        node->bn_key_imm = *ki;

    assert(kv->bkv_refcnt >= 0);
    ++kv->bkv_refcnt;

    return node;
}

struct bonsai_node *
bn_node_alloc(
    struct bonsai_root *        tree,
    const struct key_immediate *key_imm,
    const void *                key,
    const struct bonsai_sval *  sval)
{
    struct bonsai_node *node;
    struct bonsai_kv *  kv;

    merr_t err;

    kv = NULL;
    err = bn_kv_init(tree, key_imm, key, sval, &kv);
    if (ev(err))
        return NULL;

    node = bn_node_make(tree, NULL, NULL, kv, key_imm, 0);
    if (ev(!node))
        return NULL;

    bn_height_update(node);

    return node;
}

struct bonsai_node *
bn_node_dup(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *newnode;

    assert(node->bn_kv->bkv_refcnt > 0);

    newnode = bn_node_make(
        tree, node->bn_left, node->bn_right, node->bn_kv, &node->bn_key_imm, node->bn_flags);
    if (ev(!newnode))
        return NULL;

    newnode->bn_height = node->bn_height;

#ifdef BONSAI_TREE_DEBUG_ALLOC
    BONSAI_RCU_ATOMIC_INC(&tree->br_client.bc_dup);
#endif

    return newnode;
}

struct bonsai_node *
bn_node_dup_ext(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    struct bonsai_node *newnode;

    assert(node->bn_kv->bkv_refcnt > 0);

    newnode = bn_node_make(tree, left, right, node->bn_kv, &node->bn_key_imm, node->bn_flags);
    if (ev(!newnode))
        return NULL;

#ifdef BONSAI_TREE_DEBUG_ALLOC
    BONSAI_RCU_ATOMIC_INC(&tree->br_client.bc_dup);
#endif

    return newnode;
}
