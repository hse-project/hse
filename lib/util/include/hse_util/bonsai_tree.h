/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * This file contains the type definitions and prototypes of bonsai
 * tree implementation
 */

#ifndef HSE_BONSAI_TREE_H
#define HSE_BONSAI_TREE_H

#include <hse_util/arch.h>
#include <hse_util/atomic.h>
#include <hse_util/spinlock.h>
#include <hse_util/key_util.h>
#include <hse_util/cursor_heap.h>
#include <hse_util/hse_err.h>
#include <hse_util/slist.h>
#include <hse_util/rcu.h>

/* clang-format off */

/* Bonsai tree static config params...
 */
#define HSE_BT_BALANCE_THRESHOLD    (2)
#define HSE_BT_HEIGHT_MAX           (32)
#define HSE_BT_SLABSZ               (PAGE_SIZE * 8)
#define HSE_BT_NODESPERSLAB \
    ((HSE_BT_SLABSZ - sizeof(struct bonsai_slab)) / sizeof(struct bonsai_node))

/* Bonsai node RCU generation count special values...
 *
 * The RCU generation count is a monotonically increasing integer which marks
 * the grace period epoch.  When a bonsai node is rotated out of the tree we
 * set its rcugen to the current epoch so that it can be freed/reclaimed in
 * the next epoch when it is no longer visible to any RCU reader.
 *
 * HSE_BN_RCUGEN_ACTIVE             node is live and possibly visible
 * HSE_BN_RCUGEN_FREE               node has been reclaimed and is free for reuse
 * HSE_BN_RCUGEN_MAX                value at which to begin rollover mitigation
 */
#define HSE_BN_RCUGEN_ACTIVE        (UINT32_MAX)
#define HSE_BN_RCUGEN_FREE          (UINT32_MAX - 1)
#define HSE_BN_RCUGEN_MAX           (UINT32_MAX - 1024)

/* If the caller is managing the k/v memory and can ensure
 * it will outlive the bonsai tree then this flag hints
 * that the bonsai tree need not copy the data.
 */
#define HSE_BTF_MANAGED             (0x0001)

enum bonsai_ior_code {
    B_IOR_INVALID       = 0,
    B_IOR_INSERTED      = 1,
    B_IOR_REPLACED      = 2,
    B_IOR_ADDED_VALUE   = 3,
    B_IOR_REP_OR_ADD    = 4,
};

#define IS_IOR_INS(_c)          ((_c) == B_IOR_INSERTED)
#define IS_IOR_REP(_c)          ((_c) == B_IOR_REPLACED)
#define IS_IOR_ADD(_c)          ((_c) == B_IOR_ADDED_VALUE)
#define IS_IOR_REPORADD(_c)     ((_c) == B_IOR_REP_OR_ADD)

#define SET_IOR_INS(_c)         ((_c) = B_IOR_INSERTED)
#define SET_IOR_REP(_c)         ((_c) = B_IOR_REPLACED)
#define SET_IOR_ADD(_c)         ((_c) = B_IOR_ADDED_VALUE)
#define SET_IOR_REPORADD(_c)    ((_c) = B_IOR_REP_OR_ADD)

/**
 * struct bonsai_skey - input key argument
 * @bsk_key_imm:
 * @bsk_key:
 * @bsk_flags:
 */
struct bonsai_skey {
    struct key_immediate  bsk_key_imm;
    const void           *bsk_key;
    u32                   bsk_flags;
};

/**
 * struct bonsai_val - bonsai tree value node
 * @bv_seqnoref:  sequence number reference
 * @bv_next:      ptr to next value in list
 * @bv_value:     ptr to value data
 * @bv_xlen:      opaque encoded value length
 * @bv_free:      ptr to next value in free list *bkv_freevalsp
 * @bv_valbuf:    value data (zero length if caller managed)
 *
 * A bonsai_val includes the value data and may be on both the bnkv_values
 * list and the free list at the same time.
 *
 * Note that the value length (@bv_xlen) is an opaque encoding of compressed
 * and uncompressed value lengths so one must use the bonsai_val_*len()
 * functions to decode it.
 */
struct bonsai_val {
    uintptr_t          bv_seqnoref;
    struct bonsai_val *bv_next;
    void              *bv_value;
    u64                bv_xlen;
    struct bonsai_val *bv_free;
    char               bv_valbuf[];
};

/**
 * bonsai_val_ulen() - return uncompressed value length
 * @bv: ptr to a bonsai val
 *
 * bonsai_val_ulen() returns the uncompressed length (in bytes) of the
 * given bonsai value.  Note that uncompressed value lengths are always
 * greater than compressed value lengths.
 */
static HSE_ALWAYS_INLINE uint
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
static HSE_ALWAYS_INLINE uint
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
static HSE_ALWAYS_INLINE uint
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
static HSE_ALWAYS_INLINE uint
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
 * @bkv_key:        ptr to key
 * @bkv_flags:      BKV_FLAG_*
 * @bkv_voffset:    offset to embedded bonsai_val
 * @bkv_valcnt:     user-managed length of bkv_values list
 * @bkv_values:     user-managed list of values
 * @bkv_prev:
 * @bkv_next:
 * @bkv_es:
 * @bkv_keybuf:     key data (zero length if caller-managed)
 *
 * A bonsai_kv includes the key and a list of bonsai_val objects.
 * The bonsai_kv and initial bonsai_val are allocated in one chunk.
 */
struct bonsai_kv {
    struct key_immediate    bkv_key_imm;
    char                   *bkv_key;
    u16                     bkv_flags;
    u16                     bkv_voffset;
    u32                     bkv_valcnt;
    struct bonsai_val *     bkv_values;
    struct bonsai_kv *      bkv_prev;
    struct bonsai_kv *      bkv_next;
    struct element_source  *bkv_es;
    struct bonsai_val      *bkv_freevals;
    char                    bkv_keybuf[];
};

/**
 * There is one such structure for each node in the tree.
 *
 * struct bonsai_node - structure representing interal nodes of tree
 * @bn_key_imm: cache of first KI_DLEN_MAX bytes of bn_kv->bkv_key[]
 * @bn_height:  height of the node.
 * @bn_rcugen:  rcu grace period gen when can be reclaimed
 * @bn_left:    bonsai tree child node linkage
 * @bn_right:   bonsai tree child node linkage
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
    struct key_immediate  bn_key_imm;
    int32_t               bn_height;
    uint32_t              bn_rcugen;
    struct bonsai_node   *bn_left;
    struct bonsai_node   *bn_right;
    struct bonsai_kv     *bn_kv;
} HSE_ALIGNED(64);

_Static_assert(sizeof(struct bonsai_node) == 64, "bonsai node too large");

/* struct bonsai_slab -
 * @bs_rnodes:    list of reclaimed nodes
 * @bs_rnodec:    number of reclaimed node allocations
 * @bs_entryc:    next entry from bs_entryv[] to allocate
 * @bs_nodec:     number of node allocations from entryv
 * @bs_canfree:   ok to free via free()
 * @bs_next:      linkage for various gc lists
 * @bs_slabinfo   ptr to owning slabinfo record
 * @bs_rcugen     rcu gen of last reclaim attempt
 * @bs_entryv:    fixed size bonsai node heap
 */
struct bonsai_slab {
    struct bonsai_node     *bs_rnodes;
    uint32_t                bs_rnodec;
    uint32_t                bs_nodec;
    uint32_t                bs_entryc;
    uint8_t                 bs_canfree;
    struct bonsai_slab     *bs_next;
    struct bonsai_slabinfo *bs_slabinfo;
    uint64_t                bs_rcugen;
    void                   *bs_magic;
    struct bonsai_node      bs_entryv[];
};

/* struct bonsai_slabinfo -
 * @bsi_slab:     current slab from which to allocate entries
 * @bsi_freeq:    list of slabs that have reclaimed nodes
 * @bsi_rnodec:   count of recycled node allocations
 * @bsi_nodec:    count of node entry allocations
 * @bsi_slabc:    count of slab allocations
 * @bsi_slab0:    initial slab (embedded)
 */
struct bonsai_slabinfo {
    struct bonsai_slab *bsi_slab HSE_ALIGNED(SMP_CACHE_BYTES);
    struct bonsai_slab *bsi_freeq;
    uint                bsi_rnodec;
    uint                bsi_nodec;
    uint                bsi_slabc;
    struct bonsai_slab *bsi_slab0;
};

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
typedef void bonsai_ior_cb(
    void *                rock,
    enum bonsai_ior_code *code,
    struct bonsai_kv *    kv,
    struct bonsai_val *   val,
    struct bonsai_val **  old_val,
    uint                  height);

/**
 * struct bonsai_root - bonsai tree parameters
 * @br_bounds:          indicates bounds are established and lcp
 * @br_height:          tree current max height
 * @br_root:            pointer to the root of bonsai_tree
 * @br_cheap:           ptr to cheap (or nil for malloc backed tree)
 * @br_iorcb:           client's callback for insert or replace
 * @br_iorcb_arg:       opaque arg for br_iorcb()
 * @br_rootslab:        contains nodes low in tree and OOM nodes
 * @br_slabbase:        ptr to base of slabs embedded in bonsai_root
 * @br_key_alloc:       total number of keys ever allocated
 * @br_val_alloc:       total number of values ever allocated
 * @br_freekeys:        list of keys to be garbage collected
 * @br_kv:              a circular k/v list, next=head, prev=tail
 * @br_gc_lock:         protects gc queues between user and rcu callback
 * @br_gc_waitq:        list of slabs waiting to get on ready queue
 * @br_gc_readyq:       list of slabs waiting on rcu callback
 * @br_gc_rcugen_start: next rcu grace period generation
 * @br_gc_rcugen_done:  last rcu grace period generation
 * @br_gc_activeq:      list of slabs undergoing gc
 * @br_gc_emptyq:       list of empty slabs undergoing gc
 * @br_gc_freekeys:     list of key undergoing gc
 * @br_gc_sched:        rcu callback list node
 * @br_slabinfov:       vector of per-skidx slab headers
 * @br_data:            storage for embedded slabs
 */
struct bonsai_root {
    atomic_t                br_bounds HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    struct bonsai_node     *br_root;
    struct cheap           *br_cheap;
    bonsai_ior_cb          *br_ior_cb;
    void                   *br_ior_cbarg;
    struct bonsai_slabinfo *br_rootslab;
    void                   *br_slabbase;
    void                   *br_magic;

    /* Everything from here to the end of the structure is bzero'd
     * by bn_reset().
     */
    int                     br_height HSE_ALIGNED(SMP_CACHE_BYTES);
    uint                    br_key_alloc;
    uint                    br_val_alloc;
    struct bonsai_kv       *br_freekeys;


    spinlock_t              br_gc_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    struct bonsai_slab     *br_gc_waitq;

    struct bonsai_slab     *br_gc_readyq HSE_ALIGNED(SMP_CACHE_BYTES);
    atomic_t                br_gc_rcugen_start;

    atomic_t                br_gc_rcugen_done HSE_ALIGNED(SMP_CACHE_BYTES);
    struct bonsai_slab     *br_gc_activeq;
    struct bonsai_slab     *br_gc_emptyq;
    struct bonsai_kv       *br_gc_freekeys;

    uint64_t                br_gc_latstart  HSE_ALIGNED(SMP_CACHE_BYTES);
    uint64_t                br_gc_latsum_gp;
    uint64_t                br_gc_latsum_gc;
    struct rcu_head         br_gc_sched_rcu;

    /* There are eight per-skidx slabs and one additional "rootslab".
     * The root slab is used to satisfy node allocation requests for
     * nodes low in the tree and node allocation requests that would
     * otherwise fail because we're unable to allocate a new slab.
     */
    struct bonsai_slabinfo  br_slabinfov[8 + 1];

    /* br_kv must be last as it contains a flexible array member.
     */
    struct bonsai_kv        br_kv;
};

/* clang-format off */

/**
 * bn_create() - Initialize tree and client info.
 * @cheap:     memory allocator
 * @cb:        insert or replace callback
 * @rock:      per-tree rock entity for client
 * @tree:      bonsai tree instance (output parameter)
 *
 * Return:
 */
merr_t
bn_create(
    struct cheap        *cheap,
    bonsai_ior_cb       *cb,
    void                *cbarg,
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
    const struct bonsai_sval *sval);

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
bn_skey_init(const void *key, s32 klen, u32 flags, u16 index, struct bonsai_skey *skey)
{
    key_immediate_init(key, klen, index, &skey->bsk_key_imm);
    skey->bsk_key = key;
    skey->bsk_flags = flags;
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

#endif /* HSE_BONSAI_TREE_H */
