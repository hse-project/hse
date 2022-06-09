/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_H
#define HSE_KVS_CN_KVSET_H

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/omf_kmd.h>
#include <hse_ikvdb/kvset_view.h>
#include <hse_ikvdb/cndb.h>

#include "blk_list.h"
#include "kv_iterator.h"

struct kvset;
struct kv_iterator;
struct kvs_ktuple;
struct kvset_vblk_map;
struct mpool;
struct kvs_rparams;
struct kvs_buf;
struct cndb;
struct workqueue_struct;
struct mbset;
struct cn_kvdb;
struct cn_tree;
struct cn_merge_stats;
struct kvset_stats;

struct kvset_list_entry {
    struct list_head le_link;
    struct kvset *   le_kvset;
};

enum kvset_iter_flags {
    kvset_iter_flag_mcache = (1u << 0),
    kvset_iter_flag_reverse = (1u << 1),
    kvset_iter_flag_fullscan = (1u << 2),
};

/**
 * struct kvset_meta - describes the content of a kvset
 * @km_hblk:        hblock
 * @km_kblk_list:   reference to vector of kblock ids
 * @km_vblk_list:   reference to vector of vblock ids
 * @km_dgen:        kvset generation id
 * @km_vused:       sum of lengths of referenced values across all vblocks
 * @km_node_offset: cn tree node offset
 * @km_node_level:  cn tree node level
 * @km_nodeid:      cn tree node id
 * @km_compc:       compaction count (prevents repeated kvset compaction)
 * @km_capped:      cn is capped
 * @km_restored:    kvset is being restored from the cndb
 *
 * This structure is passed between the MDC and kvset_create.
 */
struct kvset_meta {
    struct kvs_block km_hblk;
    struct blk_list km_kblk_list;
    struct blk_list km_vblk_list;
    uint64_t        km_dgen;
    uint64_t        km_vused;
    uint32_t        km_node_offset;
    uint32_t        km_scatter;
    uint16_t        km_node_level;
    uint64_t        km_nodeid;
    uint16_t        km_compc;
    bool            km_capped;
    bool            km_restored;
};

enum {
    KVSET_MISS_KEY_TOO_SMALL = -1,
    KVSET_MISS_KEY_TOO_LARGE = -2,
};

merr_t
kvset_init(void) HSE_COLD;

void
kvset_fini(void) HSE_COLD;

u64
kvset_get_tag(struct kvset *kvset);

/* MTF_MOCK_DECL(kvset) */

/**
 * kvset_get_ref() - Obtain a ref on a kvset
 *
 * Caller must be holding the kvset_list_rlock or already have a
 * reference count on this kvset.
 */
/* MTF_MOCK */
void
kvset_get_ref(struct kvset *kvset);

/**
 * kvset_put_ref() - Release a ref on a kvset
 *
 * No lock need be held to call kvset_put_ref().  If this is it is the last
 * ref, then:
 *   - the kvset has already been removed the read path and can longer be
 *     found to have another ref added, and
 *   - the 'struct kvset' object destructor will be called.
 */
/* MTF_MOCK */
void
kvset_put_ref(struct kvset *kvset);

/**
 * kvset_create() - Create a kvset
 * @tree:  cn tree handle
 * @tag:   cndb tag for this kvset
 * @meta:  kvset_meta data -- what to create
 * @kvset: (output) newly constructed kvset object
 */
/* MTF_MOCK */
merr_t
kvset_create(struct cn_tree *tree, u64 tag, struct kvset_meta *meta, struct kvset **kvset);

/**
 * Preload/discard hblock mcache map pages
 *
 * This function is used to either preload or discard pages from @p kvset
 * kvset's mcache mapped hblock, depending upon @p madvice:
 *
 * @p MADV_WILLNEED: Initiate readahead preloading of all the pages
 * @p MADV_DONTNEED: Mark all the pages as currently unneeded
 *
 * See madvise(2) for more informaation.
 *
 * @param kvset kvset pointer
 * @param advice readahead mode for madvise(2)
 * @param leaves madvise(2) leaf nodes as well
 */
/* MTF_MOCK */
void
kvset_madvise_hblk(struct kvset *kvset, int advice, bool leaves);

/**
 * kvset_madvise_kblks() - preload/discard kblock mcache map pages
 * @kvset:    kvset pointer
 * @advice:   readahead mode for madvise()
 *
 * This function is used to either preload or discard pages from all
 * the given kvset's mcache mapped kblocks, depending upon %madvice:
 *
 *  %MADV_WILLNEED:  Initiate readahead preloading of all the pages
 *  %MADV_DONTNEED:  Mark all the pages as currently unneeded
 *
 * See madvise(2) for more informaation.
 */
/* MTF_MOCK */
void
kvset_madvise_kblks(struct kvset *kvset, int advice, bool blooms, bool leaves);

/**
 * kvset_madvise_vblks() - preload/discard vblock mcache map pages
 * @kvset:    kvset pointer
 * @advice:   readahead mode for madvise()
 *
 * This function is used to either preload or dicsard pages from all
 * the given kvset's mcache mapped vblocks, depending upon %madvice:
 *
 *  %MADV_WILLNEED:  Initiate readahead preloading of all the pages
 *  %MADV_DONTNEED:  Mark all the pages as currently unneeded
 *
 * See madvise(2) for more informaation.
 */
/* MTF_MOCK */
void
kvset_madvise_vblks(struct kvset *kvset, int advice);

void
kvset_madvise_capped(struct kvset *kvset, int advice);

/**
 * kvset_madvise_vmaps() - Change kvset vblock mcache map memory use mode
 * @kvset:    kvset pointer
 * @advice:   readahead mode for madvise()
 *
 * This function is used to change the mcache map readahead mode for all
 * mcache maps in the given kvset's vblocks, where %adivce may be one
 * of the following:  %MADV_RANDOM, %MADV_DONTNEED
 *
 * Note that the default mode for mcache maps is %MADV_RANDOM, which
 * effectively disables readahead.
 *
 * See madvise(2) for more informaation.
 */
/* MTF_MOCK */
void
kvset_madvise_vmaps(struct kvset *kvset, int advice);

/**
 * kvset_purge_vmaps() - Purge kvset vblock mcache map
 * @kvset:    kvset pointer
 */
/* MTF_MOCK */
void
kvset_purge_vmaps(struct kvset *kvset);

/* MTF_MOCK */
merr_t
kvset_create2(
    struct cn_tree *   tree,
    uint64_t           kvsetid,
    struct kvset_meta *meta,
    uint               vbset_cnt_len,
    uint *             vbset_cnts,
    struct mbset ***   vbset_vecs,
    struct kvset **    kvset);

/* MTF_MOCK */
merr_t
kvset_delete_log_record(struct kvset *ks, struct cndb_txn *txn);

/* MTF_MOCK */
void
kvset_mark_mblocks_for_delete(struct kvset *kvset, bool keepv);

/* MTF_MOCK */
struct mbset **
kvset_get_vbsetv(struct kvset *km, uint *vbsetc);

/* MTF_MOCK */
void
kvset_list_add(struct kvset *kvset, struct list_head *head);

/* MTF_MOCK */
void
kvset_list_add_tail(struct kvset *kvset, struct list_head *head);

/**
 * kvset_get_min_key() - Get the smallest key in a kvset
 *
 * @ks:   struct kvset handle.
 * @min_key:  (output) reference to the smallest key
 * @min_klen: (output) length of @min_key
 *
 * NOTE: @min_key is valid as long as kvset exists. Callers must copy the key, or
 * keep a ref to the kvset.
 */
/* MTF_MOCK */
void
kvset_get_min_key(struct kvset *ks, const void **min_key, uint *min_klen);

/**
 * kvset_get_max_key() - Get the largest key in a kvset
 *
 * @ks:   struct kvset handle.
 * @max_key:  (output) reference to the largest key
 * @max_klen: (output) length of @max_key
 *
 * NOTE: @max_key is valid as long as kvset exists. Callers must copy the key, or
 * keep a ref to the kvset.
 */
/* MTF_MOCK */
void
kvset_get_max_key(struct kvset *ks, const void **max_key, uint *max_klen);

/* MTF_MOCK */
u64
kvset_ctime(const struct kvset *kvset);

bool
kvset_has_ptree(const struct kvset *ks) HSE_NONNULL(1);

/**
 * kvset_kblk_start() - return index of kblock where this key may reside
 * @kvset:   kvset to search
 * @key:     key to search for
 * @len:     length of key (if < 0, check for prefix match)
 * @reverse: whether caller intends to iterate in reverse.
 *
 * Returns < 0 if key not plausibly in kvset:
 *      KVSET_MISS_KEY_TOO_SMALL if key is less than least key in kvset
 *      KVSET_MISS_KEY_TOO_LARGE if key is larger than the max key in kvset
 * else returns the index of the kblk in the kvset kblk list.
 */
/* MTF_MOCK */
int
kvset_kblk_start(struct kvset *kvset, const void *key, int len, bool reverse);

/**
 * kvset_lookup() - Search a kvset for a key and return its value
 * @kvset:  kvset to search
 * @kt:     key to search for
 * @kdisc:  key discriminator
 * @seq:    sequence number
 * @result: (output) one of NOT_FOUND, FOUND_VAL, or FOUND_TMB (tombstone)
 * @vbuf:   (output) value if result==FOUND_VAL
 *                   If vbuf->b_buf is NULL, a buffer large enough to hold the
 *                   value will be allocated.
 */
merr_t
kvset_lookup(
    struct kvset *         kvset,
    struct kvs_ktuple *    kt,
    const struct key_disc *kdisc,
    u64                    seq,
    enum key_lookup_res *  res,
    struct kvs_buf *       vbuf);

struct query_ctx;

merr_t
kvset_wbti_alloc(void **wbti);

void
kvset_wbti_free(void *wbti);

merr_t
kvset_pfx_lookup(
    struct kvset *         km,
    struct kvs_ktuple *    kt,
    const struct key_disc *kdisc,
    u64                    seq,
    enum key_lookup_res *  res,
    void *                 wbti,
    struct kvs_buf *       kbuf,
    struct kvs_buf *       vbuf,
    struct query_ctx *     qctx);

/* MTF_MOCK */
u64
kvset_get_workid(struct kvset *km);

/* MTF_MOCK */
void
kvset_set_workid(struct kvset *km, u64 id);

/**
 * kvset_get_nth_vblock_len() - Get len of useful data in nth vblock
 */
/* MTF_MOCK */
u64
kvset_get_nth_vblock_len(struct kvset *km, u32 index);

/* MTF_MOCK */
void
kvset_stats(const struct kvset *ks, struct kvset_stats *stats);

/* MTF_MOCK */
const struct kvset_stats *
kvset_statsp(const struct kvset *ks);

/* MTF_MOCK */
uint
kvset_get_scatter_score(struct kvset *self);

/* MTF_MOCK */
uint
kvset_get_scatter_pct(struct kvset *self);

/* MTF_MOCK */
void
kvset_set_scatter_pct(struct kvset *self, uint spct);

/* MTF_MOCK */
u8 *
kvset_get_hlog(struct kvset *km);

/* MTF_MOCK */
uint
kvset_get_compc(struct kvset *km);

/* MTF_MOCK */
uint
kvset_get_vgroups(struct kvset *km);

/* MTF_MOCK */
struct cn_tree *
kvset_get_tree(struct kvset *kvset);

/**
 * kvset_iter_create() - Create iterator to traverse all entries in a kvset
 * @kvset:     kvset handle
 * @io_workq:  workqueue to assist with async I/O (see %FLAG_MBREAD)
 * @vra_wq:    workqueue for vblock readahead requests
 * @pc:
 * @flags:     option flags (see below)
 * @kv_iter:   (output) iterator
 *
 * Flags:
 *   - %kvset_iter_flag_reverse: Iterate over keys in reverse.  Can only
 *     be used with mcache map based iteration.
 *   - %kvset_iter_flag_mcache: If set, use mcache maps to access
 *     mblock data.  If not set, access data with mblock read.
 *
 * Notes:
 *   - @io_workq is ignored when iterating with mcache maps.
 *   - With read-based compaction, if @io_workq is NULL, then mblock reads are
 *     issued synchronously using a single buffer.  If @io_workq is provided,
 *     then double buffering is used to overlap reads with iteration work.
 *   - The iterator is destroyed by calling the iterator's release method, for
 *     example: kv_iter->kvsi_ops->kvsi_release(kv_iter);
 *
 *     IMPORTANT:  If successful, kvset_iter_create() adopts one reference
 *     on %kvset from the caller.  Put another way, the caller must obtain
 *     a kvset reference to be given to the kv_iterator.
 *     We currently have only two use cases:  One in which the caller
 *     has a pre-acquired reference to give (cn_tree_cursor_create()),
 *     and one in which the caller has to explicitly acquire a
 *     reference to give (cn_tree_prepare_compaction()).  In both
 *     cases kvset_iter_release() releases the adopted reference.
 */
/* MTF_MOCK */
merr_t
kvset_iter_create(
    struct kvset *           kvset,
    struct workqueue_struct *io_workq,
    struct workqueue_struct *vra_wq,
    struct perfc_set *       pc,
    enum kvset_iter_flags    flags,
    struct kv_iterator **    kv_iter);

/* MTF_MOCK */
void
kvset_iter_release(struct kv_iterator *handle);

/* MTF_MOCK */
void
kvset_iter_set_stats(struct kv_iterator *handle, struct cn_merge_stats *stats);

/* MTF_MOCK */
merr_t
kvset_iter_set_start(struct kv_iterator *kv_iter, int start);

/**
 * kvset_iter_seek() - efficiently moves the iterator to starting kblk (or eof)
 * @handle:  kv_iter from kvset_iter_create
 * @key:     key to seek
 * @len:     length of key; if negative, key is a prefix
 */
/* MTF_MOCK */
merr_t
kvset_iter_seek(struct kv_iterator *handle, const void *key, int len, bool *eof);

/* MTF_MOCK */
void
kvset_iter_mark_eof(struct kv_iterator *handle);

/* MTF_MOCK */
struct element_source *
kvset_iter_es_get(struct kv_iterator *kvi);

/* MTF_MOCK */
struct kvset *
kvset_iter_kvset_get(struct kv_iterator *handle);

/* MTF_MOCK */
void *
kvset_from_iter(struct kv_iterator *iv);

/* MTF_MOCK */
merr_t
kvset_iter_next_key(struct kv_iterator *handle, struct key_obj *kobj, struct kvset_iter_vctx *vc);

/* MTF_MOCK */
struct element_source *
kvset_iter_es_get(struct kv_iterator *handle);

/* MTF_MOCK */
merr_t
kvset_iter_val_get(
    struct kv_iterator *    handle,
    struct kvset_iter_vctx *vc,
    enum kmd_vtype          vtype,
    uint                    vbidx,
    uint                    vboff,
    const void **           vdata,
    uint *                  vlen,
    uint *                  complen);

/* MTF_MOCK */
bool
kvset_iter_next_vref(
    struct kv_iterator *    handle,
    struct kvset_iter_vctx *vc,
    u64 *                   seq,
    enum kmd_vtype *        vtype,
    uint *                  vbidx,
    uint *                  vboff,
    const void **           vdata,
    uint *                  vlen,
    uint *                  complen);

/**
 * kvset_keep_vblocks - populate a vblock map from many-to-one
 * @out:  the map to populate
 * @iv:   the vector of input iterators
 * @niv:  the number of iterator
 *
 * This function creates a map of vblock offsets necessary
 * for correctly locating the values when used in a k-compaction.
 *
 * Return: @out is populated with both a list of vblkids and a map
 * of vr_index offsets, keyed by iterator index.
 *
 * NB: This function lives in keep.c so it can be tested.
 */
merr_t
kvset_keep_vblocks(struct kvset_vblk_map *out, struct kv_iterator **iv, int niv);

/* MTF_MOCK */
void
kvset_maxkey(struct kvset *ks, const void **maxkey, u16 *maxklen);

/* MTF_MOCK */
void
kvset_minkey(struct kvset *ks, const void **minkey, u16 *minklen);

/*-  kvset checker  ---------------------------------------------------------*/

struct vb_meta;

typedef void
print_cb(char *, ...);

/**
 * kc_print_reg() - register a print function for kvset and kblock checkers
 * @verbose:    verbose or not
 * @print_func: callback function to be registered. If null, the registered
 *              callback function remains unchanged.
 *
 * If no function is registered, the default print function is used - which
 * prints to hse_log.
 */
void
kc_print_reg(bool verbose, print_cb print_func);

struct vb_meta *
kc_vblock_meta(struct mpool *ds, struct blk_list *list);

/**
 * kc_kblock_check() - Verify correctness of a kblock's contents and its nodeloc
 * @ds:          handle to the kvdb dataset
 * @kblkid:      kblock id
 * @vb_meta:     vblock list and properties.
 */
merr_t
kc_kblock_check(struct mpool *ds, u64 kblkid, struct vb_meta *vb_meta);

/**
 * kc_kvset_check() - Verify correctness of a kvset
 * @ds:     handle to the kvdb dataset
 * @cp:     kvs create-time params
 * @meta:   kvset_meta data
 * @tree:   cn tree ptr
 */
merr_t
kc_kvset_check(struct mpool *ds, struct kvs_cparams *cp, struct kvset_meta *meta, struct cn_tree *tree);

/**
 * kvset_iter_next_val_direct() -  read value via direct io
 * @handle: handle to kv iterator
 */
/* MTF_MOCK */
merr_t
kvset_iter_next_val_direct(
    struct kv_iterator *handle,
    enum kmd_vtype      vtype,
    uint                vbidx,
    uint                vboff,
    void *              vdata,
    uint                vlen,
    uint                bufsz);

#if HSE_MOCKING
#include "kvset_ut.h"
#endif /* HSE_MOCKING */

#endif
