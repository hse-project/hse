/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This file contains the type definitions and prototypes of bonsai
 * tree implementation
 */

#ifndef HSE_BONSAI_TREE_H
#define HSE_BONSAI_TREE_H

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/key_util.h>
#include <hse_util/cursor_heap.h>
#include <hse_util/hse_err.h>
#include <hse_util/slist.h>
#include <hse_util/rcu.h>

#define BONSAI_TREE_BALANCE_THRESHOLD 4
#define BONSAI_MUT_LISTC 2

enum bonsai_ior_code {
    B_IOR_INSERTED = 1,
    B_IOR_REPLACED = 2,
    B_IOR_ADDED_VALUE = 3,
    B_IOR_REP_OR_ADD = 4,
};

/*
 * Bonsai value flags
 */
#define BV_TXNVAL (0x01)

#define IS_IOR_INS(_c) ((_c) == B_IOR_INSERTED)
#define IS_IOR_REP(_c) ((_c) == B_IOR_REPLACED)
#define IS_IOR_ADD(_c) ((_c) == B_IOR_ADDED_VALUE)
#define IS_IOR_REPORADD(_c) ((_c) == B_IOR_REP_OR_ADD)

#define SET_IOR_INS(_c) ((_c) = B_IOR_INSERTED)
#define SET_IOR_REP(_c) ((_c) = B_IOR_REPLACED)
#define SET_IOR_ADD(_c) ((_c) = B_IOR_ADDED_VALUE)
#define SET_IOR_REPORADD(_c) ((_c) = B_IOR_REP_OR_ADD)

/**
 * struct bonsai_skey - input key argument
 * @key:
 * @key_imm:
 */
struct bonsai_skey {
    const void *         bsk_key;
    struct key_immediate bsk_key_imm;
};

/**
 * struct bonsai_val - bonsai tree value node
 * @bv_next:      ptr to next value in list
 * @bv_free:      ptr to next value in free list
 * @bv_seqnoref:  sequence number reference
 * @bv_priv:      client's private value
 * @bv_flags:     flags, used by the client
 * @bv_xlen:      opaque encoded value length
 * @bv_valuep:    ptr to value
 * @bv_value:     value data
 *
 * A bonsai_val includes the value data and may be on both the bnkv_values
 * list and the free list at the same time.
 *
 * Note that the value length (@bv_xlen) is an opaque encoding of compressed
 * and uncompressed value lengths so one must use the bonsai_val_*len()
 * functions to decode it.
 */
struct bonsai_val {
    struct bonsai_val *bv_next;
    struct bonsai_val *bv_free;
    uintptr_t          bv_seqnoref;
    atomic64_t         bv_priv;
    unsigned int       bv_flags;
    u64                bv_xlen;
    void              *bv_valuep;
    char               bv_value[];
};

/**
 * bonsai_val_ulen() - return uncompressed value length
 * @bv: ptr to a bonsai val
 *
 * bonsai_val_ulen() returns the uncompressed length (in bytes) of the
 * given bonsai value.  Note that uncompressed value lengths are always
 * greater than compressed value lengths.
 */
static __always_inline uint
bonsai_val_ulen(const struct bonsai_val *bv)
{
    return bv->bv_xlen & 0xfffffffful;
}

/**
 * bonsai_val_clen() - return compressed value length
 * @bv: ptr to a bonsai val
 *
 * bonsai_val_clen() returns the compressed length (in bytes) of the
 * given bonsai value.  If the value is not compressed then zero is
 * returned.  Note that compressed value lengths are always less than
 * uncompressed value lengths.
 */
static __always_inline uint
bonsai_val_clen(const struct bonsai_val *bv)
{
    return bv->bv_xlen >> 32;
}

/**
 * bonsai_val_vlen() - return in-core value length
 * @bv: ptr to a bonsai val
 *
 * bonsai_val_vlen() returns the in-core length (in bytes) of the
 * given bonsai value, irrespective of whether or not it is compressed.
 */
static __always_inline uint
bonsai_val_vlen(const struct bonsai_val *bv)
{
    return bonsai_val_clen(bv) ?: bonsai_val_ulen(bv);
}

/**
 * struct bonsai_sval - input value argument
 * @bsv_val:      pointer to value data
 * @bsv_xlen:     opaque encoded value length
 * @bsv_seqnoref: sequence number reference
 *
 * Note that the value length (@bsv_xlen) is an opaque encoding of compressed
 * and uncompressed value lengths so one must use the bonsai_sval_vlen()
 * function decode it.
 */
struct bonsai_sval {
    void     *bsv_val;
    u64       bsv_xlen;
    uintptr_t bsv_seqnoref;
};

/**
 * bonsai_sval_vlen() - return in-core value length
 * @bsv: pointer to a bonsai sval
 *
 * bonsai_sval_vlen() returns the in-core length (in bytes) of the
 * given bonsaid svalue, irrespective of whether or not it is compressed.
 */
static __always_inline uint
bonsai_sval_vlen(const struct bonsai_sval *bsv)
{
    uint clen = bsv->bsv_xlen >> 32;
    uint vlen = bsv->bsv_xlen & 0xfffffffful;

    return clen ?: vlen;
}

#define BKV_FLAG_PTOMB 0x01
#define BKV_FLAG_TOMB_HEAD 0x02

/**
 * struct bonsai_kv - bonsai tree key/value node
 * @bkv_key_imm:
 * @bkv_flags:
 * @bkv_refcnt:
 * @bkv_values:
 * @bkv_prev:
 * @bkv_next:
 * @bkv_es:
 * @bkv_mnext:
 * @bkv_txmnext:
 * @bkv_txpend:
 * @bkv_key:
 *
 * A bonsai_kv includes the key and a list of bonsai_val objects.
 */
struct bonsai_kv {
    struct key_immediate   bkv_key_imm;
    u16                    bkv_flags;
    struct bonsai_val *    bkv_values;
    struct bonsai_kv *     bkv_prev;
    struct bonsai_kv *     bkv_next;
    struct bonsai_kv *     bkv_tomb;
    struct element_source *bkv_es;
    struct s_list_head     bkv_mnext[BONSAI_MUT_LISTC];
    struct s_list_head     bkv_txmnext[BONSAI_MUT_LISTC];
    struct s_list_head     bkv_txpend;
    char                   bkv_key[];
};

/**
 * There is one such structure for each node in the tree.
 *
 * struct bonsai_node - structure representing interal nodes of tree
 * @bn_left:    bonsai tree child node linkage
 * @bn_right:   bonsai tree child node linkage
 * @bn_key_imm: cache of first KI_DLEN_MAX bytes of bn_kv->bkv_key[]
 * @bn_height:  height of the node.
 * @bn_kv:      ptr to a key/value node (contains full key)
 *
 * The %bn_kv, and %bn_key_imm fields are set during node initialization and
 * never change thoughout the lifetime of the node.  Hence, they need
 * no special RCU handling.
 *
 * This structure is arranged and packed so as to consume exactly one full
 * 64-byte cache line, so as to avoid false-sharing that would otherwise
 * be caused by tree update operations).
 */
struct bonsai_node {
    struct bonsai_node   *bn_left;
    struct bonsai_node   *bn_right;
    struct key_immediate  bn_key_imm;
    s32                   bn_height;
    struct bonsai_kv     *bn_kv;
} __aligned(64);

_Static_assert(sizeof(struct bonsai_node) == 64, "bonsai node too large");

/**
 * @bonsai_ior_cb: callback for insert or replace
 *
 * @rock:    per-tree rock entity passed by the client
 * @code:    enum bonsai_ior_code
 * @kv:      bonsai_kv associated with node where the new value will be
 *           inserted or replaced
 * @val:     Allocated and initialized bonsai_val element
 * @old_val: bonsai_val element replaced, code must be set to B_IOR_REPLACED
 *
 * This callback is invoked during insert or replace and is implemented by
 * the client.
 */
typedef void (*bonsai_ior_cb)(
    void *                rock,
    enum bonsai_ior_code *code,
    struct bonsai_kv *    kv,
    struct bonsai_val *   val,
    struct bonsai_val **  old_val);

/**
 * struct - bonsai_client - abstracted client instance
 * @bc_cheap:       ptr to cheap
 * @bc_iorcb:       client's callback for insert or replace
 * @bc_rock:        owner private ptr
 * @bc_slab_sz:     node slab size (bytes)
 * @bc_slab_cur:    ptr to next free node in node slab
 * @bc_slab_end:    ptr to end of node slab
 *
 * Stores client specific callback and opaque parameters.
 */
struct bonsai_client {
    struct cheap   *bc_cheap;
    bonsai_ior_cb   bc_iorcb;
    void           *bc_rock;
    size_t          bc_slab_sz;

    __aligned(SMP_CACHE_BYTES)
    struct bonsai_node *bc_slab_cur;
    struct bonsai_node *bc_slab_end;
};

/**
 * struct bonsai_root - bonsai tree parameters
 * @br_root:      pointer to the root of bonsai_tree
 * @br_bounds:    indicates bounds are established and lcp
 * @br_client:    bonsai client instance
 * @br_stack:     used by bn_ior_impl() to eliminate recursion
 * @br_kv:        a circular k/v list, next=head, prev=tail
 *
 * There is one bonsai_root for each bonsai tree.
 */
struct bonsai_root {
    struct bonsai_node  *br_root;
    atomic_t             br_bounds;
    struct bonsai_client br_client;
    uintptr_t            br_stack[40];
    struct bonsai_kv     br_kv;
};

/**
 * bn_create() - Initialize tree and client info.
 * @cheap:     memory allocator
 * @slabsz:    slab size to be used for bonsai nodes
 * @cb:        insert or replace callback
 * @rock:      per-tree rock entity for client
 * @tree:      bonsai tree instance (output parameter)
 *
 * Return:
 */
merr_t
bn_create(
    struct cheap        *cheap,
    size_t               slabsz,
    bonsai_ior_cb        cb,
    void *               rock,
    struct bonsai_root **tree);

/**
 * bn_reset() - Resets bonsai tree.
 * @tree: bonsai tree instance
 */
void
bn_reset(struct bonsai_root *tree);

/**
 * bn_destroy() - Destroys bonsai tree.
 * @tree: bonsai tree instance
 *
 * Return:
 */
void
bn_destroy(struct bonsai_root *tree);

/**
 * bn_insert_or_replace() - Inserts a given key, value pair into the tree
 * @tree: bonsai tree instance
 * @skey: bonsai_skey instance containing the key and its related info
 * @sval: bonsai_sval instance containing the value and its related info
 * @is_tomb: is the value a regular tombstone
 *
 * For multiple values support, the client specified callback
 * (bonsai_ior_cb) is invoked with the following:
 * a. Owner private pointer
 * a. The bonsai_kv instance associated with the looked-up bonsai node
 * b. An allocated and initialized value node.
 *
 * The logic to position the new value node in the bkv_values list must be
 * determined by the client. For example, the client could place the new
 * value at the front of bkv_values list or at the tail or at a position
 * determined by the rock values stored in the value nodes.
 *
 * Return   : 0 upon success, error code otherwise
 */
merr_t
bn_insert_or_replace(
    struct bonsai_root *      tree,
    const struct bonsai_skey *skey,
    const struct bonsai_sval *sval,
    const bool                is_tomb);

/**
 * bn_find() - Searches for a given key in the node
 * @tree: bonsai tree instance
 * @skey: bonsai_skey instance containing the key and its related info
 * @kv:   bonsai_kv instance containing all the values (output parameter).
 *        The logic to pick an appropriate value from kv->bkv_values is
 *        left to the client.
 *
 * - Caller must hold rcu_read_lock() across this call and while looking at kv.
 * - Caller must not modify kv.
 *
 * Return   :
 */
bool
bn_find(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv);

/**
 * bn_findGE() - Searches for a given key in the node
 * @tree: bonsai tree instance
 * @skey: bonsai_skey instance containing the key and its related info
 * @kv:   bonsai_kv instance containing all the values (output parameter).
 *        The logic to pick an appropriate value from kv->bkv_values is
 *        left to the client.
 *
 * - Caller must hold rcu_read_lock() across this call and while looking at kv.
 * - Caller must not modify kv.
 *
 * Return   :
 */
bool
bn_findGE(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv);

/**
 * bn_skiptombs_GE() - Searches for a given key in the node
 * @tree: bonsai tree instance
 * @skey: bonsai_skey instance containing the key and its related info
 * @kv:   bonsai_kv instance containing all the values (output parameter).
 *        The key returned is the smallest key >= skey,
 *        skipping contiguous tomb spans.
 *        The key returned may or may not be a tombstone.
 *        Contiguous tombspans are not strict - if one is skipped, it is valid.
 *        However, not all possible contiguous tombspans are recorded.
 *
 * - Caller must hold rcu_read_lock() across this call and while looking at kv.
 * - Caller must not modify kv.
 *
 * Return   :
 */
bool
bn_skiptombs_GE(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv);

bool
bn_find_pfx_GT(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv);

/**
 * bn_findLE() - Searches for a given key in the node
 * @tree: bonsai tree instance
 * @skey: bonsai_skey instance containing the key and its related info
 * @kv:   bonsai_kv instance containing all the values (output parameter).
 *        The logic to pick an appropriate value from kv->bkv_values is
 *        left to the client.
 *
 * - Caller must hold rcu_read_lock() across this call and while looking at kv.
 * - Caller must not modify kv.
 *
 * Return   :
 */
bool
bn_findLE(struct bonsai_root *tree, const struct bonsai_skey *skey, struct bonsai_kv **kv);

/**
 * bn_traverse() - In-order tree traversal for debugging purposes.
 * @tree: bonsai tree instance
 *
 * Return   :
 */
void
bn_traverse(struct bonsai_root *tree);

/**
 * bn_finalize() - prepare a fixated cb_tree for efficient traversal
 * @tree: bonsai tree instance
 *
 * This function performs an in-order traversal of the given bonsai tree,
 * producing an ordered doubly-linked list of all the key nodes (i.e.,
 * the struct cb_kv nodes).
 *
 * This function must only be called on a bonsai tree in the quiescent
 * state for which no further updates will occur.
 *
 * Return   :
 */
void
bn_finalize(struct bonsai_root *tree);

/**
 * Accessor functions for bonsai client specific fields
 */

/**
 * bn_skey_init() - initialize a bonsai_skey instance
 * @key:   key
 * @klen:  key length
 * @index:
 * @skey:
 */
static inline void
bn_skey_init(const void *key, s32 klen, u16 index, struct bonsai_skey *skey)
{
    skey->bsk_key = key;
    key_immediate_init(key, klen, index, &skey->bsk_key_imm);
}

/**
 * bn_sval_init() - initialize a bonsai_sval instance
 * @val:      value
 * @xlen:     value length
 * @seqnoref: sequence number reference
 * @sval:
 */
static inline void
bn_sval_init(void *val, u64 xlen, uintptr_t seqnoref, struct bonsai_sval *sval)
{
    sval->bsv_val = val;
    sval->bsv_xlen = xlen;
    sval->bsv_seqnoref = seqnoref;
}

static inline s32
bn_kv_cmp(const void *lhs, const void *rhs)
{
    const struct bonsai_kv *l = lhs;
    const struct bonsai_kv *r = rhs;

    return key_full_cmp(&l->bkv_key_imm, l->bkv_key, &r->bkv_key_imm, r->bkv_key);
}

/*
 * Max heap comparator with a caveat: A ptomb sorts before all keys w/ matching
 * prefix.
 *
 * Returns:
 *   < 0 : lhs > rhs
 *   > 0 : lhs < rhs
 *  == 0 : lhs == rhs
 *
 * Note that the return values are inverted compared to what bn_kv_cmp()
 * returns. This way heapify can be agnositic of this logic.
 */
static inline s32
bn_kv_cmp_rev(const void *lhs, const void *rhs)
{
    const struct bonsai_kv *l = lhs;
    const struct bonsai_kv *r = rhs;

    const void *r_key = r->bkv_key;
    int         r_klen = key_imm_klen(&r->bkv_key_imm);
    const void *l_key = l->bkv_key;
    int         l_klen = key_imm_klen(&l->bkv_key_imm);
    bool        l_ptomb = !!(l->bkv_flags & BKV_FLAG_PTOMB);
    bool        r_ptomb = !!(r->bkv_flags & BKV_FLAG_PTOMB);
    uint        l_skidx = key_immediate_index(&l->bkv_key_imm);
    uint        r_skidx = key_immediate_index(&r->bkv_key_imm);
    int         rc;

    rc = r_skidx - l_skidx;
    if (rc)
        return rc;

    if (!(l_ptomb ^ r_ptomb))
        return key_inner_cmp(r_key, r_klen, l_key, l_klen);

    /* exactly one of lhs and rhs is a ptomb */
    if (l_ptomb && l_klen <= r_klen) {
        rc = key_inner_cmp(r_key, l_klen, l_key, l_klen);
        if (rc == 0)
            return -1; /* l wins */
    } else if (r_ptomb && r_klen <= l_klen) {
        rc = key_inner_cmp(r_key, r_klen, l_key, r_klen);
        if (rc == 0)
            return 1; /* r wins */
    }

    return key_inner_cmp(r_key, r_klen, l_key, l_klen);
}

static inline void
bv_priv_set(struct bonsai_val *val, u64 priv)
{
    atomic64_set(&val->bv_priv, priv);
}

static inline u64
bv_priv_get(struct bonsai_val *val)
{
    return atomic64_read(&val->bv_priv);
}

static inline u8
bv_is_txn(struct bonsai_val *val)
{
    return (val->bv_flags & BV_TXNVAL);
}

static inline void
bv_set_txn(struct bonsai_val *val)
{
    val->bv_flags |= BV_TXNVAL;
}

#endif /* HSE_BONSAI_TREE_H */
