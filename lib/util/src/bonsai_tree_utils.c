/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdalign.h>

#include "bonsai_tree_pvt.h"

static void *
bn_alloc(struct bonsai_root *tree, size_t sz)
{
    if (tree->br_cheap)
        return cheap_malloc(tree->br_cheap, sz);

    return malloc(sz);
}

static struct bonsai_node *
bn_node_alloc_impl(struct bonsai_root *tree, uint skidx)
{
    struct bonsai_slabinfo *slabinfo;
    struct bonsai_slab *slab;
    struct bonsai_node *node;

    slabinfo = tree->br_slabinfov + (skidx % NELEM(tree->br_slabinfov));
    slab = slabinfo->bsi_slab;

    if (!slab || slab->bs_entryc == 0) {
        if (slab && slab != tree->br_oomslab) {
            slab->bs_next = slabinfo->bsi_empty;
            slabinfo->bsi_empty = slab;
            slabinfo->bsi_slab = NULL;

            /* [HSE_REVISIT] Initiate garbage collection... */
        }

        /* Allocate and initialize a new slab...
         */
        if (tree->br_cheap)
            slab = cheap_memalign(tree->br_cheap, alignof(*slab), tree->br_slabsz);
        else
            slab = aligned_alloc(alignof(*slab), tree->br_slabsz);

        if (HSE_UNLIKELY( !slab )) {
            slab = tree->br_oom;
            if (slab) {
                if (slab->bs_entryc == 0) {

                    /* The oom slab is empty meaning we didn't size it large
                     * enough to handle a rebalance.  We can't continue without
                     * risking a corrupted tree.
                     */
                    assert(slab->bs_entryc > 0);
                    abort();
                }

                /* All per-skidx slabs can share the oom slab.
                 */
                slabinfo->bsi_slab = slab;
                goto alloc;
            }

            tree->br_oom = tree->br_oomslab;
            slab = tree->br_oom;
        }

        slab->bs_entryc = tree->br_slabsz / sizeof(struct bonsai_node) - 1;
        slab->bs_next = NULL;

        slabinfo->bsi_slab = slab;
    }

    /* Allocate a new node from the slab, set node ID such that bn_node2slab()
     * can efficiently find the slab header.
     */
  alloc:
    node = slab->bs_entryv + --slab->bs_entryc;
    node->bn_nodeid = node - slab->bs_entryv + 1;

    slabinfo->bsi_nodes++;

    return node;
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
    if (!v)
        return NULL;

    tree->br_val_alloc++;

    v->bv_seqnoref = sval->bsv_seqnoref;
    v->bv_next = NULL;
    v->bv_value = sval->bsv_val;
    v->bv_xlen = sval->bsv_xlen;
    v->bv_free = NULL;

    if (sz > sizeof(*v)) {
        memcpy(v->bv_valbuf, sval->bsv_val, sz - sizeof(*v));
        v->bv_value = v->bv_valbuf;
    }

    return v;
}

static merr_t
bn_kv_init(
    struct bonsai_root        *tree,
    const struct bonsai_skey  *skey,
    const struct bonsai_sval  *sval,
    struct bonsai_kv         **kv_out)
{
    struct bonsai_kv *kv;
    bool managed;
    size_t sz;

    sz = sizeof(*kv);

    managed = skey->bsk_flags & HSE_BTF_MANAGED;
    if (!managed)
        sz += key_imm_klen(&skey->bsk_key_imm);

    kv = bn_alloc(tree, sz);
    if (!kv)
        return merr(ENOMEM);

    memset(kv, 0, sizeof(*kv));
    kv->bkv_key_imm = skey->bsk_key_imm;
    kv->bkv_key = (void *)skey->bsk_key; // [HSE_REVISIT] Constness...
    kv->bkv_valcnt = 1;

    if (sz > sizeof(*kv)) {
        memcpy(kv->bkv_keybuf, skey->bsk_key, sz - sizeof(*kv));
        kv->bkv_key = kv->bkv_keybuf;
    }

    kv->bkv_values = bn_val_alloc(tree, sval, managed);

    if (!kv->bkv_values) {
        kv->bkv_next = tree->br_freekeys;
        tree->br_freekeys = kv;
        kv->bkv_valcnt = 0;
        return merr(ENOMEM);
    }

    tree->br_key_alloc++;

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

    node = bn_node_alloc_impl(tree, key_immediate_index(ki));
    if (node) {
        node->bn_key_imm = *ki;
        node->bn_left = left;
        node->bn_right = right;
        node->bn_height = bn_height_max(bn_height_get(left), bn_height_get(right));
        node->bn_flags = HSE_BNF_VISIBLE;
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
    struct bonsai_node *node;
    struct bonsai_kv *kv = NULL;
    merr_t err;

    err = bn_kv_init(tree, skey, sval, &kv);
    if (err)
        return NULL;

    node = bn_node_make(tree, NULL, NULL, kv, &skey->bsk_key_imm);
    if (node) {
        //bn_height_update(node);
        node->bn_height = 1;
        return node;
    }

    kv->bkv_next = tree->br_freekeys;
    tree->br_freekeys = kv;

    return NULL;
}

struct bonsai_node *
bn_node_dup(struct bonsai_root *tree, struct bonsai_node *src)
{
    struct bonsai_node *newnode;

    newnode = bn_node_make(tree, src->bn_left, src->bn_right, src->bn_kv, &src->bn_key_imm);
    if (newnode)
        newnode->bn_height = src->bn_height;

    return newnode;
}

struct bonsai_node *
bn_node_dup_ext(
    struct bonsai_root *tree,
    struct bonsai_node *src,
    struct bonsai_node *left,
    struct bonsai_node *right)
{
    return bn_node_make(tree, left, right, src->bn_kv, &src->bn_key_imm);
}
