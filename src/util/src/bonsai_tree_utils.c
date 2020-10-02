/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/event_counter.h>

#include "bonsai_tree_pvt.h"

static inline void *
bn_alloc(struct bonsai_root *tree, size_t sz)
{
    return cheap_malloc(tree->br_client.bc_cheap, sz);
}

static inline void *
bn_node_alloc_impl(struct bonsai_root *tree)
{
    struct bonsai_client *client;
    void *mem;

    client = &tree->br_client;

    assert(client->bc_cheap);

    if (client->bc_slab_cur >= client->bc_slab_end) {
        unsigned long slabsz;

        slabsz = client->bc_slab_sz;

        mem = cheap_memalign(client->bc_cheap, __alignof(struct bonsai_node), slabsz);
        if (ev(!mem))
            return NULL;

        client->bc_slab_cur = mem;
        client->bc_slab_end = client->bc_slab_cur + (slabsz / sizeof(struct bonsai_node));
    }

    return client->bc_slab_cur++;
}

struct bonsai_val *
bn_val_alloc(struct bonsai_root *tree, const struct bonsai_sval *sval)
{
    struct bonsai_val *v;
    size_t             sz;
    uint               vlen;

    vlen = bonsai_sval_len(sval);
    sz = sizeof(*v) + vlen;

    v = bn_alloc(tree, sz);
    if (ev(!v))
        return NULL;

    v->bv_next = NULL;
    v->bv_free = NULL;
    v->bv_seqnoref = sval->bsv_seqnoref;
    v->bv_flags = 0;
    v->bv_xlen = sval->bsv_xlen;
    v->bv_valuep = sval->bsv_val;
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

    sz = sizeof(*kv) + key_imm_klen(key_imm);

    kv = bn_alloc(tree, sz);
    if (ev(!kv))
        return merr(ENOMEM);

    kv->bkv_next = NULL;
    kv->bkv_prev = NULL;
    kv->bkv_tomb = NULL;
    kv->bkv_es = NULL;

    for (i = 0; i < BONSAI_MUT_LISTC; i++) {
        INIT_S_LIST_HEAD(&kv->bkv_mnext[i]);
        INIT_S_LIST_HEAD(&kv->bkv_txmnext[i]);
    }
    INIT_S_LIST_HEAD(&kv->bkv_txpend);

    kv->bkv_flags = 0;
    kv->bkv_key_imm = *key_imm;
    memcpy(kv->bkv_key, key, key_imm_klen(key_imm));

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
    const struct key_immediate *ki)
{
    struct bonsai_node *node;

    node = bn_node_alloc_impl(tree);
    if (node) {
        node->bn_left = left;
        node->bn_right = right;
        node->bn_kv = kv;
        node->bn_height = bn_height_max(bn_height_get(left), bn_height_get(right));

        if (ki)
            node->bn_key_imm = *ki;
    }

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
    if (err)
        return NULL;

    node = bn_node_make(tree, NULL, NULL, kv, key_imm);
    if (node)
        bn_height_update(node);

    return node;
}

struct bonsai_node *
bn_node_dup(struct bonsai_root *tree, struct bonsai_node *node)
{
    struct bonsai_node *newnode;

    newnode = bn_node_make(tree, node->bn_left, node->bn_right, node->bn_kv, &node->bn_key_imm);
    if (newnode)
        newnode->bn_height = node->bn_height;

    return newnode;
}

struct bonsai_node *
bn_node_dup_ext(
    struct bonsai_root *tree,
    struct bonsai_node *node,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    return bn_node_make(tree, left, right, node->bn_kv, &node->bn_key_imm);
}
