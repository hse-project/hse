/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_KVSET_H
#define HSE_KVS_CN_KVSET_H

#include <hse/error/merr.h>
#include <hse/util/inttypes.h>
#include <hse/util/list.h>
#include <hse/util/perfc.h>

#include <hse/ikvdb/blk_list.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/ikvdb/tuple.h>
#include <hse/ikvdb/omf_kmd.h>
#include <hse/ikvdb/kvset_view.h>
#include <hse/ikvdb/cndb.h>
#include <hse/ikvdb/csched.h>

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
struct vgmap;

struct kvset_list_entry {
    struct list_head le_link;
    struct kvset *   le_kvset;
};

enum kvset_iter_flags {
    kvset_iter_flag_mmap = (1u << 0),
    kvset_iter_flag_reverse = (1u << 1),
    kvset_iter_flag_fullscan = (1u << 2),
};

/**
 * struct kvset_meta - describes the content of a kvset
 * @km_hblk:        hblock
 * @km_kblk_list:   reference to vector of kblock ids
 * @km_vblk_list:   reference to vector of vblock ids
 * @km_dgen_hi:     kvset high generation id
 * @km_dgen_lo:     kvset low generation id
 * @km_vused:       sum of lengths of referenced values across all vblocks
 * @km_vgarb:       sum of lengths of all unreferenced values across all vblocks
 * @km_nodeid:      cn tree node ID
 * @km_compc:       compaction count (prevents repeated kvset compaction)
 * @km_rule:        compaction rule ID that created this kvset
 * @km_capped:      cn is capped
 * @km_restored:    kvset is being restored from the cndb
 *
 * This structure is passed between the MDC and kvset_open().
 */
struct kvset_meta {
    uint64_t        km_hblk_id;
    struct blk_list km_kblk_list;
    struct blk_list km_vblk_list;
    uint64_t        km_dgen_hi;
    uint64_t        km_dgen_lo;
    uint64_t        km_vused;
    uint64_t        km_vgarb;
    uint64_t        km_nodeid;
    uint16_t        km_compc;
    uint16_t        km_rule;
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
 * kvset_open() - Open a kvset
 * @tree:  cn tree handle
 * @tag:   cndb tag for this kvset
 * @meta:  kvset_meta data -- what to create
 * @kvset: (output) newly constructed kvset object
 */
/* MTF_MOCK */
merr_t
kvset_open(struct cn_tree *tree, u64 tag, struct kvset_meta *meta, struct kvset **kvset);

/**
 * Preload/discard hblock memory mapped pages
 *
 * This function is used to either preload or discard pages from @p kvset
 * kvset's memory mapped hblock, depending upon @p madvice:
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
 * kvset_madvise_kblks() - preload/discard kblock memory mapped pages
 * @kvset:    kvset pointer
 * @advice:   readahead mode for madvise()
 *
 * This function is used to either preload or discard pages from all
 * the given kvset's memory mapped kblocks, depending upon %madvice:
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
 * kvset_madvise_vblks() - preload/discard vblock memory mapped pages
 * @kvset:    kvset pointer
 * @advice:   readahead mode for madvise()
 *
 * This function is used to either preload or dicsard pages from all
 * the given kvset's memory mapped vblocks, depending upon %madvice:
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
 * kvset_madvise_vmaps() - Change kvset vblock memory mapped pages use mode
 * @kvset:    kvset pointer
 * @advice:   readahead mode for madvise()
 *
 * This function is used to change the memory map readahead mode for all
 * memory maps in the given kvset's vblocks, where %adivce may be one
 * of the following:  %MADV_RANDOM, %MADV_DONTNEED
 *
 * See madvise(2) for more informaation.
 */
/* MTF_MOCK */
void
kvset_madvise_vmaps(struct kvset *kvset, int advice);

/* MTF_MOCK */
merr_t
kvset_open2(
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

void
kvset_mark_mbset_for_delete(struct kvset *ks, bool delete_blks);

void
kvset_purge_blklist_add(struct kvset *ks, struct blk_list *blks);

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
 * kvset_get_max_nonpt_key() - Get the largest key in a kvset
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
kvset_get_max_nonpt_key(struct kvset *ks, const void **max_key, uint *max_klen);

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

/*
 * kvset_younger() - returns true if ks1 is younger than ks2
 *
 * NOTE:
 * - if dgen_hi(ks1) > dgen_hi(ks2), then return true
 * - if dgen_hi(ks1) < dgen_hi(ks2), then return false
 * - if dgen_hi(ks1) == dgen_hi(ks2), then
 *   - if dgen_lo(ks1) >= dgen_lo(ks2), then return true, else return false
 */
/* MTF_MOCK */
bool
kvset_younger(const struct kvset *ks1, const struct kvset *ks2);

/* Any thread may call kvset_get_work() to examine the returned value.
 * Threads holding the tree lock may dereference the value only if
 * kvset is on the tree node list.
 */
/* MTF_MOCK */
const void *
kvset_get_work(struct kvset *km);

/* Only the monitor thread (csched) sets work from NULL to non-null (while
 * holding the tree read lock).  In some circumstances, compaction threads
 * will reset work to NULL, but only while holding the tree write lock.
 */
/* MTF_MOCK */
void
kvset_set_work(struct kvset *km, const void *work);

/* MTF_MOCK */
void
kvset_set_rule(struct kvset *ks, enum cn_rule rule);

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
u8 *
kvset_get_hlog(struct kvset *km);

/* MTF_MOCK */
uint64_t
kvset_get_id(const struct kvset *ks);

/* MTF_MOCK */
uint32_t
kvset_get_compc(const struct kvset *ks);

/* MTF_MOCK */
void
kvset_set_compc(struct kvset *ks, uint32_t compc);

/* MTF_MOCK */
uint
kvset_get_vgroups(const struct kvset *km);

size_t
kvset_get_kwlen(const struct kvset *ks);

size_t
kvset_get_vwlen(const struct kvset *ks);

/* MTF_MOCK */
struct cn_tree *
kvset_get_tree(struct kvset *kvset);

struct vblock_desc *
kvset_get_nth_vblock_desc(struct kvset *ks, uint32_t index);

/* MTF_MOCK */
void
kvset_set_nodeid(struct kvset *kvset, uint64_t nodeid);

/* MTF_MOCK */
uint64_t
kvset_get_dgen_lo(const struct kvset *kvset);

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
 *     be used with memory map based iteration.
 *   - %kvset_iter_flag_mmap: If set, use memory maps to access
 *     mblock data.  If not set, access data with mblock read.
 *
 * Notes:
 *   - @io_workq is ignored when iterating with memory maps.
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
 * @gmap: vgroup map to populate
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
kvset_keep_vblocks(
    struct kvset_vblk_map  *out,
    struct vgmap          **vgmap,
    struct kv_iterator    **iv,
    int                     niv);

/* MTF_MOCK */
void
kvset_maxkey(const struct kvset *ks, const void **maxkey, uint16_t *maxklen);

/* MTF_MOCK */
void
kvset_minkey(const struct kvset *ks, const void **minkey, uint16_t *minklen);

/* MTF_MOCK */
void
kvset_max_ptkey(const struct kvset *ks, const void **max, uint16_t *maxlen);

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

/**
 * vgmap_alloc() - Allocates a vgroup map
 * @nvgroups: number of vgroups
 */
struct vgmap *
vgmap_alloc(uint32_t nvgroups);

/**
 * vgmap_free() - Frees the specified vgroup map
 * @vgmap: vgroup map
 */
void
vgmap_free(struct vgmap *vgmap);

/**
 * vgmap_vbidx_src2out - returns the output vblock index for a given source index
 * @vgmap:     vgroup map
 * @vbidx_src: source vblock index
 */
merr_t
vgmap_vbidx_src2out(struct vgmap *vgmap, uint16_t vbidx_src, uint16_t *vbidx_out);

/**
 * vgmap_vbidx_out_start - returns the first vblock index for a given vgmap index
 * @ks:    kvset handle
 * @vgidx: vgmap array index
 */
uint16_t
vgmap_vbidx_out_start(struct kvset *ks, uint32_t vgidx);

/**
 * vgmap_vbidx_out_end - returns the last vblock index for a given vgmap index
 * @ks:    kvset handle
 * @vgidx: vgmap array index
 */
/* MTF_MOCK */
uint16_t
vgmap_vbidx_out_end(struct kvset *ks, uint32_t vgidx);

/**
 * vgmap_vbidx_set - sets the target vgroup map for a given vgmap index based on
 *                   the source vgmap, source and target output vblock indexes
 * @vgmap_src:     source vgroup map
 * @vbidx_src_out: output vblock index in the source vgmap
 * @vgmap_tgt:     target vgroup map (output)
 * @vbidx_tgt_out: output vblock index in the target vgmap
 * @vgidx:         vgmap_array_index
 */
merr_t
vgmap_vbidx_set(
    struct vgmap *vgmap_src,
    uint16_t      vbidx_src_out,
    struct vgmap *vgmap_tgt,
    uint16_t      vbidx_tgt_out,
    uint32_t      vgidx);

#if HSE_MOCKING
#include "kvset_ut.h"
#endif /* HSE_MOCKING */

#endif
