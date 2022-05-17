/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kblock_builder
#include "kblock_builder.h"

#include <hse/limits.h>
#include <hse/kvdb_perfc.h>

#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvs_rparams.h>

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/assert.h>
#include <hse_util/bloom_filter.h>
#include <hse_util/event_counter.h>
#include <hse_util/perfc.h>
#include <hse_util/hlog.h>
#include <hse_util/log2.h>
#include <hse_util/vlb.h>
#include <hse_util/logging.h>
#include <hse_util/keycmp.h>

#include "omf.h"
#include "blk_list.h"
#include "kblock_reader.h"
#include "wbt_builder.h"
#include "wbt_reader.h"
#include "cn_mblocks.h"
#include "cn_metrics.h"
#include "cn_perfc.h"

#include <mpool/mpool.h>

extern struct tbkt sp3_tbkt;

#define KBLOCK_HDR_PAGES 1
#define KBLOCK_HDR_LEN ((KBLOCK_HDR_PAGES) * (PAGE_SIZE))

#define HSP_HASH_MAX_KEYS (16 * 1024)

/**
 * DOC: Overview
 * This file implements a @kblock_builder.  It also defines @hash_set and
 * @curr_kblock types.  @hash_set exists to keep track of key hashes for
 * creating bloom filters.  @curr_kblock contains the logic for building a
 * single kblock.  @kblock_builder contains the logic for building multiple
 * kblocks with the same @dgen (data generation) value.
 */

/**
 * struct hash_set_part - part of a hash set
 * @part_link: for linking multiple parts into a hash set
 * @n_hashes: number of key hashes stored in this hash set
 * @hashvec: array of hash values
 *
 * This struct is used to store a subset of the key hashes used to create
 * a kblock Bloom filter.
 *
 * Sizing considerations;
 *
 * With %HSP_HASH_MAX_KEYS defined as 16K, this struct is approximately 128KB
 * in size.  Thus, every 16K keys will result in a 128KB allocation for
 * storing the key hashes.
 *
 * A max size kblock is 32MB (%KBLOCK_MAX_SIZE), and can hold about
 * 32MB/4K==8K wbtree nodes. If we pretend they're all leaf nodes, it will
 * hold about 1 million keys (8K nodes * ~128 key/node), which will require
 * 1M/16K==64 hash_set_part structs.
 */
struct hash_set_part {
    struct list_head part_link;
    u32              n_hashes;
    u64              hashvec[HSP_HASH_MAX_KEYS];
};

/**
 * struct hash_set - stores key hashes for building Bloom filters
 * @part_list: a list of full "parts"
 * @curr_part: the current part, not yet full
 */
struct hash_set {
    struct list_head      part_list;
    struct hash_set_part *curr_part;
};

/**
 * struct curr_kblock - context for building a single kblock
 * @wbtree: Wbtree builder handle.
 * @max_pgc:  Max size of kblock in pages.
 * @wbt_pgc:  Number of pages reserved for wbtree.
 * @blm_pgc:  Number of pages reserved for Bloom filter.
 * @bloom_elt_cap: Number of keys Bloom filter can hold at current size
 * @hash_set:  Hash set to store key hashes. Used to build
 *             Bloom filter at end of kblock construction.
 * @num_keys:  Number of keys in kblock.
 * @num_tombstones:  Number of keys in kblock that have tombstone values.
 * @total_key_bytes: Sum of all key lengths.
 * @total_val_bytes: Sum of all value lengths.
 * @hlog: kblocks's hlog, last kblock stores the kvsets hlog instead
 *
 * Description:
 *
 *   Struct curr_kblock contains the context for the construction of a single
 *   kblock.  The kblock is constructed in memory and keys are added one at a
 *   time.  When the kblock has reached the maximum supported kblock size or
 *   when there are no more keys to store, an mblock is allocated and the
 *   in-memory image is written but not committed.  The user of this object
 *   is responsible for committing or aborting the mblock.
 *
 * Notes:
 *
 *   The space reserved for the Bloom filter grows as keys are added to the
 *   kblock.  As a result, the "free" space avalable for the wbtree shrinks
 *   due to growth of the wbtree itself and of the Bloom filter.
 *
 * Kblock Layout:
 *
 *   Kblock header occupies first KBLOCK_HDR_PAGES pages.
 *
 *   Wbtree occupies next wbt_pgc pages.
 *
 *   Bloom tree occupies next blm_pbc pages.
 */
struct curr_kblock {

    struct wbb *        wbtree;
    struct kvs_rparams *rp;
    struct kvs_cparams *cp;
    struct perfc_set *  pc;

    uint64_t total_key_bytes;
    uint64_t total_val_bytes;
    uint32_t num_keys;
    uint32_t num_tombstones;

    uint32_t max_size;
    uint32_t max_pgc;
    uint32_t blm_pgc;
    uint32_t wbt_pgc;

    uint                   blm_elt_cap;
    struct hash_set        hash_set;
    struct bf_bithash_desc desc;

    void *kblk_hdr;
    struct hlog *hlog;
    void *bloom;
    uint  bloom_len;
    uint  bloom_alloc_len;
    uint  bloom_used_max;
};

static HSE_ALWAYS_INLINE uint32_t
free_pgc(struct curr_kblock *kblk)
{
    const uint32_t used = KBLOCK_HDR_PAGES + HLOG_PGC + kblk->blm_pgc + kblk->wbt_pgc;

    assert(kblk->max_pgc >= used);
    if (kblk->max_pgc >= used)
        return kblk->max_pgc - used;

    return 0;
}

/**
 * struct kblock_builder - Create kblocks from a stream of key/value pairs.
 * @ds: the dataset in which kblocks will be created
 * @finished_kblks: list of finished kblocks (written, not committed)
 * @curr: the kblock currently being built
 * @finished: mark builder as finished (end of life)
 * @kvset_hlog: kvset's hlog to be stored in the last kblock
 * @max_size: Maximum mblock size of all configured media classes.
 */
struct kblock_builder {
    struct mpool *             ds;
    struct cn *                cn;
    struct kvs_rparams *       rp;
    struct kvs_cparams *       cp;
    struct perfc_set *         pc;
    struct hlog *              kvset_hlog;
    struct cn_merge_stats *    mstats;
    struct blk_list            finished_kblks;
    struct curr_kblock         curr;
    struct wbb *               ptree;
    enum hse_mclass_policy_age agegroup;
    bool                       finished;
    uint                       pt_pgc;
    uint                       pt_max_pgc;
    uint32_t                   max_size;
    uint64_t                   seqno_min;
    uint64_t                   seqno_max;
};

/**
 * mblk_blow_chunks() - Split a large mpool_mblock_write request into a
 *                      sequence of smaller requests.
 * @self:      kblock builder
 * @mbid:      mblock id
 * @iov:       iovec
 * @iov_cnt:   NELEM(iovec)
 * @chunk_len: length of each write
 *
 * Mpool's mpool_mblock_write() function imposes the following restrictions:
 *   - Each iov buffer must be page-aligned.
 *   - Each iov length must be a multiple of PAGE_SIZE.
 *   - The sum of iov lengths must be a multiple of the mblock's
 *     optimal write size, except for the final write to an mblock
 *     (which must still be multiple of PAGE_SIZE).
 *
 * More on the optimal write size:
 *   - The optimal write size is determined by mpool (and should
 *     correspond to an efficient IO size for the underlying device).
 *   - The optimal write size is a multiple of PAGE_SIZE.
 *   - All mblocks in a media class instance have the same optimal write size.
 *
 * The function exists because simply using a large power power of 2 such
 * as 1MiB as the write length doesn't always work.
 *
 * This function seems more complicated than necessary because it modifies
 * (and restores) iov_base and iov_len in the caller's iovec to avoid
 * allocating a temporary iovec.
 */
static merr_t
mblk_blow_chunks(
    struct kblock_builder *self,
    u64                    mbid,
    struct iovec *         iov,
    uint                   iov_cnt,
    uint                   chunk_len)
{
    merr_t err;

    uint written = 0;
    uint tot_len = 0;
    uint i;

    uint ax, aoff, alen, alen_orig;
    uint bx, blen_orig;
    uint wlen, need;

    u64                    dt = 0;
    struct cn_merge_stats *stats = self->mstats;

    /* ax, aoff, alen, bx, blen explained:
     *
     * Each iteration of the loop calls mpool_mblock_write on a subsequence
     * of the caller's iovec.  Local vars ax and bx are indices into
     * the caller's iovec and mark this subsequence.
     *
     * For example, if ax == 2 and bx == 4, then write is called on iovec
     * segments 2, 3 and 4 as follows:
     *
     *    mpool_mblock_write(ds, mbid, iov + ax, bx - ax + 1);
     *
     * Note however that the first (ax==2) and last segments (bx==4)
     * may need to be trimmed.  Local vars aoff and alen identify
     * the tail of iov[ax] that will be written (on this iteration).
     */

    /* Compute total len to control loop termination. */
    for (i = 0; i < iov_cnt; i++)
        tot_len += iov[i].iov_len;

    ax = aoff = 0;
    while (tot_len > written) {

        wlen = tot_len - written;
        if (wlen > chunk_len)
            wlen = chunk_len;

        /* need == number of bytes we need for the next mblock_write */
        need = wlen;

        alen_orig = iov[ax].iov_len;
        alen = alen_orig - aoff;

        if (alen == 0) {
            /* Nothing left in segment 'a'. */
            aoff = 0;
            ax++;
            continue;
        }

        if (alen >= need) {
            /* Segment 'a' has enough data for a write.
             * Trim front and back end of this segment, issue
             * write, then restore segment base and length.
             */
            iov[ax].iov_base += aoff;
            iov[ax].iov_len = need;

            if (stats)
                dt = get_time_ns();
            err = mpool_mblock_write(self->ds, mbid, iov + ax, 1);
            if (ev(err))
                return err;
            if (stats)
                dt = get_time_ns() - dt;

            iov[ax].iov_base -= aoff;
            iov[ax].iov_len = alen_orig;

            if (alen == need) {
                /* Done with this segment. */
                aoff = 0;
                ax++;
            } else {
                /* This segment has more data. */
                aoff += need;
            }

        } else {
            /* Segment 'a' is short.  Loop through following
             * segments until we have enough.  In this case we
             * also have to trim and restore segment 'b' (but only
             * its length).
             */
            need -= alen;
            bx = ax + 1;
            while (need > iov[bx].iov_len)
                need -= iov[bx++].iov_len;

            iov[ax].iov_base += aoff;
            iov[ax].iov_len = alen;

            if (need) {
                blen_orig = iov[bx].iov_len;
                iov[bx].iov_len = need;
            }

            if (stats)
                dt = get_time_ns();
            err = mpool_mblock_write(self->ds, mbid, iov + ax, bx - ax + 1);
            if (ev(err))
                return err;
            if (stats)
                dt = get_time_ns() - dt;

            iov[ax].iov_base -= aoff;
            iov[ax].iov_len = alen_orig;

            if (need) {
                /* Seg 'b' was trimmed, thus it still has data.
                 * Restore and set 'aoff' to the amt of data
                 * consumed from 'b' ('b' becomes the next 'a').
                 */
                iov[bx].iov_len = blen_orig;
                aoff = need;
            } else {
                /* Seg 'b' was not trimmed. */
                aoff = 0;
            }

            ax = bx;
        }

        if (stats)
            count_ops(&stats->ms_kblk_write, 1, wlen, dt);

        written += wlen;

        perfc_inc(self->pc, PERFC_RA_CNCOMP_WREQS);
        perfc_add(self->pc, PERFC_RA_CNCOMP_WBYTES, wlen);
    }
    return 0;
}

/*----------------------------------------------------------------
 * Hash Sets
 */

void
hash_set_init(struct hash_set *hs)
{
    INIT_LIST_HEAD(&hs->part_list);
    hs->curr_part = 0;
}

static merr_t
hash_set_add(struct hash_set *hs, const struct key_obj *kobj)
{
    if (!hs->curr_part) {
        hs->curr_part = malloc(sizeof(*hs->curr_part));
        if (ev(!hs->curr_part))
            return merr(ENOMEM);
        hs->curr_part->n_hashes = 0;
        list_add_tail(&hs->curr_part->part_link, &hs->part_list);
    }

    assert(hs->curr_part->n_hashes < HSP_HASH_MAX_KEYS);

    hs->curr_part->hashvec[hs->curr_part->n_hashes++] = key_obj_hash64(kobj);

    /* If full, then use next part.  If next is null, allocate new
     * part next time one is added.
     */
    if (hs->curr_part->n_hashes == HSP_HASH_MAX_KEYS)
        hs->curr_part = list_next_entry_or_null(hs->curr_part, part_link, &hs->part_list);
    return 0;
}

void
hash_set_reset(struct hash_set *hs)
{
    struct hash_set_part *part;

    hs->curr_part = 0;

    list_for_each_entry (part, &hs->part_list, part_link) {
        part->n_hashes = 0;
        if (!hs->curr_part)
            hs->curr_part = part;
    }
}

void
hash_set_free(struct hash_set *hs)
{
    struct hash_set_part *part;
    struct hash_set_part *tmp;

    list_for_each_entry_safe (part, tmp, &hs->part_list, part_link)
        free(part);
}

/**
 * DOC: struct curr_kblock API
 *
 * There are four "external" APIs (i.e., called directly by struct
 * kblock_bulder).  External APIs are named "kblock_*", and "internal"
 * APIs are named "_kblock_*".
 *
 * "External" APIs:
 *
 * kblock_init() -- initialize caller supplied struct.
 *
 * kblock_add_entry() -- Add one entry to kblock.
 *
 * kblock_finish() -- allocate and write an mblock with kblock data (does
 * not commit the mblock).
 *
 * kblock_free() -- free resources
 */
/**
 * kblock_init - initialize caller-supplied struct curr_kblock
 *
 * Allocates a large buffer (%max_size bytes) to hold an in-memory
 * kblock image, and creates a 'struct wbb' object.
 */
static merr_t
kblock_init(
    struct curr_kblock *kblk,
    struct kvs_cparams *cp,
    struct kvs_rparams *rp,
    struct perfc_set *  pc,
    uint32_t            max_size)
{
    merr_t err;

    memset(kblk, 0, sizeof(*kblk));

    hash_set_init(&kblk->hash_set);

    kblk->max_size = max_size;
    kblk->max_pgc = max_size / PAGE_SIZE;
    kblk->rp = rp;
    kblk->cp = cp;
    kblk->pc = pc;
    kblk->desc = bf_compute_bithash_est(rp->cn_bloom_prob);

    err = hlog_create(&kblk->hlog, HLOG_PRECISION);
    if (ev(err))
        return err;

    err = wbb_create(&kblk->wbtree, kblk->wbt_pgc + free_pgc(kblk), &kblk->wbt_pgc);
    if (ev(err)) {
        hlog_destroy(kblk->hlog);
        return err;
    }

    return 0;
}

static void
kblock_reset(struct curr_kblock *kblk)
{
    kblk->max_pgc = kblk->max_size / PAGE_SIZE;

    kblk->total_key_bytes = 0;
    kblk->total_val_bytes = 0;
    kblk->num_keys = 0;
    kblk->num_tombstones = 0;

    kblk->blm_pgc = 0;
    kblk->blm_elt_cap = 0;
    kblk->bloom_len = 0;

    hash_set_reset(&kblk->hash_set);

    hlog_reset(kblk->hlog);
    wbb_reset(kblk->wbtree, &kblk->wbt_pgc);
}

/**
 * kblock_free - free curr_kblock resources
 */
static void
kblock_free(struct curr_kblock *kblk)
{
    vlb_free(kblk->bloom, kblk->bloom_used_max);
    free_aligned(kblk->kblk_hdr);

    wbb_destroy(kblk->wbtree);
    hlog_destroy(kblk->hlog);
    hash_set_free(&kblk->hash_set);
    memset(kblk, 0, sizeof(*kblk));
}

static bool
kblock_is_empty(struct curr_kblock *kblk)
{
    return kblk->num_keys == 0;
}

/**
 * kblock_add_entry() - add an entry to a kblock
 * @kblk: handle
 * @kobj: key to add
 * @kmd, @kmd_len: omf encoded key metadata
 * @stats: REQUIRED stats about key and its values
 * @added: true if key was added, false if no space in kblock
 */
static merr_t
kblock_add_entry(
    struct curr_kblock *  kblk,
    const struct key_obj *kobj,
    const void *          kmd,
    uint                  kmd_len,
    struct kbb_key_stats *stats,
    bool *                added)
{
    merr_t err = 0;

    *added = false;

    if (kblk->rp->cn_bloom_create) {
        size_t tree_sfx_len = kblk->cp->sfx_len;

        /* Ensure we have enough pages reserved for bloom filters. */
        if (kblk->num_keys + 1 > kblk->blm_elt_cap) {
            if (!free_pgc(kblk))
                return 0;
            kblk->blm_pgc++;
            kblk->blm_elt_cap = bf_element_estimate(kblk->desc, kblk->blm_pgc * PAGE_SIZE);
        }

        /* Add key's hash to hash_set. Hash only on the soft prefix. */
        if (tree_sfx_len) {
            struct key_obj ko = *kobj;
            size_t         min_sfx_len;

            min_sfx_len = min_t(size_t, tree_sfx_len, ko.ko_sfx_len);
            ko.ko_sfx_len -= min_sfx_len;
            ko.ko_pfx_len -= tree_sfx_len - min_sfx_len;
            err = hash_set_add(&kblk->hash_set, (const void *)&ko);
        } else {
            err = hash_set_add(&kblk->hash_set, kobj);
        }

        if (ev(err))
            return err;
    }

    /* update wbtree */
    err = wbb_add_entry(
        kblk->wbtree,
        kobj,
        stats->nvals,
        kmd,
        kmd_len,
        kblk->wbt_pgc + free_pgc(kblk),
        &kblk->wbt_pgc,
        added);
    /* Out of space indicated by err==0 and added==false. */
    if (ev(err) || !*added)
        return err;

    /* update metrics */
    kblk->num_keys++;
    kblk->total_key_bytes += key_obj_len(kobj);
    kblk->total_val_bytes += stats->tot_vlen;
    kblk->num_tombstones += stats->ntombs;

    return 0;
}

/**
 * _kblock_finish_bloom() - finalize wbtree and Bloom filter regions
 * @blm_hdr: (output) Bloom filter header
 */
static merr_t
_kblock_finish_bloom(struct curr_kblock *kblk, struct bloom_hdr_omf *blm_hdr)
{
    struct bloom_filter   bloom;
    struct hash_set_part *part;

    if (kblk->num_keys == 0 || kblk->rp->cn_bloom_create == 0) {
        assert(kblk->blm_pgc == 0);
        memset(&bloom, 0, sizeof(bloom));
    } else {
        kblk->bloom_len = kblk->blm_pgc * PAGE_SIZE;

        if (kblk->bloom_len > kblk->bloom_alloc_len) {
            kblk->bloom_alloc_len = roundup(kblk->bloom_len, 1u << 20);

            vlb_free(kblk->bloom, kblk->bloom_used_max);

            kblk->bloom = vlb_alloc(kblk->bloom_alloc_len);
            if (ev(!kblk->bloom)) {
                kblk->bloom_len = 0;
                kblk->bloom_alloc_len = 0;
                return merr(ENOMEM);
            }
        }

        kblk->bloom_used_max = max_t(uint, kblk->bloom_used_max, kblk->bloom_len);

        memset(kblk->bloom, 0, kblk->bloom_len);
        bf_filter_init(&bloom, kblk->desc, kblk->num_keys, kblk->bloom, kblk->bloom_len);
        list_for_each_entry (part, &kblk->hash_set.part_list, part_link) {
            bf_filter_insert_by_hashv(&bloom, part->hashvec, part->n_hashes);
        }
    }

    /* Construct Bloom header */
    memset(blm_hdr, 0, sizeof(*blm_hdr));
    omf_set_bh_magic(blm_hdr, BLOOM_OMF_MAGIC);
    omf_set_bh_version(blm_hdr, BLOOM_OMF_VERSION);
    omf_set_bh_bitmapsz(blm_hdr, bloom.bf_bitmapsz);
    omf_set_bh_modulus(blm_hdr, bloom.bf_modulus);
    omf_set_bh_bktshift(blm_hdr, bloom.bf_bktshift);
    omf_set_bh_rotl(blm_hdr, bloom.bf_rotl);
    omf_set_bh_n_hashes(blm_hdr, bloom.bf_n_hashes);

    return 0;
}

/**
 * _kblock_make_header() - prepare kblock omf header for writing
 * @wbt_hdr: (input) Wbtree header
 * @blm_hdr: (input) Bloom filter header
 *
 * Caller must ensure the kblock is not empty.
 *
 * Kblock header layout:
 *
 *    struct kblock_hdr_omf;
 *    pad to 8 bytes;
 *    wbtree header;
 *    pad to 8 bytes;
 *    bloom filter header;
 *    pad so that min key is at end of page, min & max keys are 8-byte aligned
 *    max key;
 *    pad to 8 bytes;
 *    min key;
 */
static void
_kblock_make_header(
    struct curr_kblock *   kblk,
    struct wbb         *   ptree,
    struct wbt_hdr_omf *   wbt_hdr,
    struct wbt_hdr_omf *   pt_hdr,
    uint                   pt_pgc,
    struct bloom_hdr_omf * blm_hdr,
    u64                    seqno_min,
    u64                    seqno_max,
    struct kblock_hdr_omf *hdr)
{
    void *          base;
    struct key_obj *min_kobj, *max_kobj;
    unsigned        off;
    const unsigned  align = 7;

    struct key_obj  tmp_kobj;
    unsigned char   tmp_kobj_buf[HSE_KVS_KEY_LEN_MAX];
    unsigned int    tmp_kobj_bufsz = sizeof(tmp_kobj_buf);

    assert(kblk->num_keys > 0);

    memset(hdr, 0, KBLOCK_HDR_LEN);

    off = 0;

    assert(
        sizeof(*hdr) + sizeof(*wbt_hdr) + sizeof(*blm_hdr) + sizeof(*pt_hdr) + 4 * align +
            2 * HSE_KBLOCK_OMF_KLEN_MAX <=
        PAGE_SIZE);

    omf_set_kbh_magic(hdr, KBLOCK_HDR_MAGIC);
    omf_set_kbh_version(hdr, KBLOCK_HDR_VERSION);
    omf_set_kbh_entries(hdr, kblk->num_keys);
    omf_set_kbh_tombs(hdr, kblk->num_tombstones);
    omf_set_kbh_key_bytes(hdr, kblk->total_key_bytes);
    omf_set_kbh_val_bytes(hdr, kblk->total_val_bytes);

    /* wbtree header is right after kblock_hdr at an 8-byte boundary */
    off += sizeof(*hdr);
    off = (off + align) & ~align;

    omf_set_kbh_wbt_hoff(hdr, off);
    omf_set_kbh_wbt_hlen(hdr, sizeof(*wbt_hdr));

    /* bloom header is next, also at an 8-byte boundary */
    off += omf_kbh_wbt_hlen(hdr);
    off = (off + align) & ~align;

    omf_set_kbh_blm_hoff(hdr, off);
    omf_set_kbh_blm_hlen(hdr, sizeof(*blm_hdr));

    off += omf_kbh_blm_hlen(hdr);
    off = (off + align) & ~align;

    omf_set_kbh_pt_hoff(hdr, off);
    omf_set_kbh_pt_hlen(hdr, sizeof(*pt_hdr));

    /* get min/max keys */
    wbb_min_max_keys(kblk->wbtree, &min_kobj, &max_kobj);
    if (ptree) {
        struct key_obj *pt_min, *pt_max;
        uint minklen, maxklen;
        uint minptlen, maxptlen;
        int rc;
        bool pad_and_copy = false;

        wbb_min_max_keys(ptree, &pt_min, &pt_max);

        minklen  = key_obj_len(min_kobj);
        maxklen  = key_obj_len(max_kobj);
        minptlen = key_obj_len(pt_min);
        maxptlen = key_obj_len(pt_max);

        if (minptlen) {
            if (minklen) {
                rc = key_obj_cmp(pt_min, min_kobj);
                if (rc < 0)
                    min_kobj = pt_min;
            } else {
                min_kobj = pt_min;
            }
        }

        if (maxptlen) {
            if (maxklen) {
                rc = key_obj_cmp(pt_max, max_kobj);
                if (rc > 0)
                    pad_and_copy = true;
            } else {
                pad_and_copy = true;
            }
        }

        /* [HSE_REVISIT] Why do we need the padding? */
        if (pad_and_copy) {
            uint len;

            key_obj_copy(tmp_kobj_buf, tmp_kobj_bufsz, &len, pt_max);
            memset(tmp_kobj_buf + len, 0xff, tmp_kobj_bufsz - len);
            key2kobj(&tmp_kobj, tmp_kobj_buf, tmp_kobj_bufsz);
            max_kobj = &tmp_kobj;
        }
    }

#ifndef NDEBUG
    if (omf_wbt_kmd_pgc(wbt_hdr)) {
        uint minkey_len = key_obj_len(min_kobj);
        uint maxkey_len = key_obj_len(max_kobj);

        assert(0 < minkey_len && minkey_len <= HSE_KVS_KEY_LEN_MAX);
        assert(0 < maxkey_len && maxkey_len <= HSE_KVS_KEY_LEN_MAX);
    }

    assert(HSE_KVS_KEY_LEN_MAX <= HSE_KBLOCK_OMF_KLEN_MAX);
#endif

    /* min key is at last 8-byte boundary that accommodates the min key */
    off = (PAGE_SIZE - HSE_KBLOCK_OMF_KLEN_MAX) & ~align;
    omf_set_kbh_min_koff(hdr, off);
    omf_set_kbh_min_klen(hdr, key_obj_len(min_kobj));

    /* max key is right before min key at an 8-byte boundary */
    off = (off - HSE_KBLOCK_OMF_KLEN_MAX) & ~align;
    omf_set_kbh_max_koff(hdr, off);
    omf_set_kbh_max_klen(hdr, key_obj_len(max_kobj));

    /* make sure bloom header doesn't overlap with max key */
    assert(omf_kbh_max_koff(hdr) >= omf_kbh_pt_hoff(hdr) + sizeof(*pt_hdr));

    /* make sure max key doesn't overlap with min key */
    assert(omf_kbh_min_koff(hdr) >= omf_kbh_max_koff(hdr) + key_obj_len(max_kobj));

    /* Set offset and length for wbtree, bloom and hlog regions. */
    omf_set_kbh_wbt_doff_pg(hdr, KBLOCK_HDR_PAGES);
    omf_set_kbh_wbt_dlen_pg(hdr, kblk->wbt_pgc);

    omf_set_kbh_blm_doff_pg(hdr, KBLOCK_HDR_PAGES + kblk->wbt_pgc);
    omf_set_kbh_blm_dlen_pg(hdr, kblk->blm_pgc);

    omf_set_kbh_hlog_doff_pg(hdr, KBLOCK_HDR_PAGES + kblk->wbt_pgc + kblk->blm_pgc);
    omf_set_kbh_hlog_dlen_pg(hdr, HLOG_PGC);

    if (pt_pgc) {
        omf_set_kbh_pt_doff_pg(hdr, KBLOCK_HDR_PAGES + kblk->wbt_pgc + kblk->blm_pgc + HLOG_PGC);
        omf_set_kbh_pt_dlen_pg(hdr, pt_pgc);
    }

    omf_set_kbh_min_seqno(hdr, seqno_min);
    omf_set_kbh_max_seqno(hdr, seqno_max);

    /* Copy wbtree, bloom and min/max keys into header page.
     * Use void* 'base' for ptr arithmetic.
     */
    base = hdr;
    memcpy(base + omf_kbh_wbt_hoff(hdr), wbt_hdr, sizeof(*wbt_hdr));
    memcpy(base + omf_kbh_blm_hoff(hdr), blm_hdr, sizeof(*blm_hdr));
    memcpy(base + omf_kbh_pt_hoff(hdr), pt_hdr, sizeof(*pt_hdr));

    key_obj_copy(base + omf_kbh_max_koff(hdr), HSE_KVS_KEY_LEN_MAX, 0, max_kobj);
    key_obj_copy(base + omf_kbh_min_koff(hdr), HSE_KVS_KEY_LEN_MAX, 0, min_kobj);
}

size_t
kbb_estimate_alen(struct cn *cn, size_t wlen, enum hse_mclass mclass)
{
    u64 zonealloc_unit;

    zonealloc_unit = cn_mpool_dev_zone_alloc_unit_default(cn, mclass);
    return cn_mb_est_alen(
        KBLOCK_MAX_SIZE, zonealloc_unit, wlen, CN_MB_EST_FLAGS_TRUNCATE | CN_MB_EST_FLAGS_POW2);
}

/**
 * kblock_finish() - allocate and write an mblock with kblock data
 *
 * Finalize wbtree and Bloom filter regions, allocate an appropriately sized
 * mblock, and write all kblock data to it.  Does not commit the mblock.
 *
 * This function unconditionally invokes kblock_free().
 */
static merr_t
kblock_finish(struct kblock_builder *bld, struct wbb *ptree, struct hlog *hlog)
{
    struct bloom_hdr_omf      blm_hdr;
    struct wbt_hdr_omf        wbt_hdr = { 0 };
    struct wbt_hdr_omf        pt_hdr = { 0 };
    struct mblock_props       mbprop;
    struct mpool_mclass_props mc_props;

    struct curr_kblock *   kblk = &bld->curr;
    struct cn_merge_stats *stats = bld->mstats;
    struct mclass_policy * mpolicy = cn_get_mclass_policy(bld->cn);

    struct iovec *iov = NULL;
    uint          iov_cnt = 0;
    uint          iov_max;
    uint          i, chunk;
    size_t        wlen;
    uint32_t      flags = 0;

    merr_t err;
    u64    blkid = 0;
    uint   pt_pgc = 0;
    u64    tstart = 0;
    u64    kblocksz;

    enum hse_mclass mclass;

    /* Allocate kblock hdr */
    if (!kblk->kblk_hdr) {
        kblk->kblk_hdr = alloc_page_aligned(KBLOCK_HDR_LEN);
        if (ev(!kblk->kblk_hdr)) {
            err = merr(ENOMEM);
            goto errout;
        }
    }

    /* Include wbtree pages from main and ptree and add 3 more iov members for
     * the kblock header, bloom and hlog
     */
    iov_max = 3 + 1 + wbb_max_inodec_get(kblk->wbtree) + wbb_kmd_pgc_get(kblk->wbtree);
    if (ptree && wbb_entries(ptree))
        iov_max += 1 + wbb_max_inodec_get(ptree) + wbb_kmd_pgc_get(ptree);

    iov = malloc(sizeof(*iov) * iov_max);
    if (ev(!iov))
        return merr(ENOMEM);

    /* Header is first entry in iovec */
    iov_cnt = 1;
    iov[0].iov_base = kblk->kblk_hdr;
    iov[0].iov_len = KBLOCK_HDR_LEN;

    /* Finalize the wbtree.  May increase kblk->wbt_pgc. */
    assert(kblk->wbtree);
    wbb_hdr_init(kblk->wbtree, &wbt_hdr);
    if (wbb_entries(kblk->wbtree)) {
        err = wbb_freeze(
            kblk->wbtree,
            &wbt_hdr,
            kblk->wbt_pgc + free_pgc(kblk),
            &kblk->wbt_pgc,
            iov + iov_cnt,
            iov_max,
            &i);
        if (ev(err))
            goto errout;
        iov_cnt += i;
    } else {
        kblk->wbt_pgc = 0;
    }

    /* Finalize Bloom filter. */
    err = _kblock_finish_bloom(kblk, &blm_hdr);
    if (ev(err))
        goto errout;
    if (kblk->bloom_len) {
        iov[iov_cnt].iov_base = kblk->bloom;
        iov[iov_cnt].iov_len = kblk->bloom_len;
        iov_cnt++;
    }

    /* Finalize HyperLogLog. */
    iov[iov_cnt].iov_base = hlog_data(hlog);
    iov[iov_cnt].iov_len = HLOG_PGC * PAGE_SIZE;
    iov_cnt++;

    /* Finalize ptomb tree */
    wbb_hdr_init(ptree, &pt_hdr);
    if (ptree && wbb_entries(ptree)) {
        pt_pgc = bld->pt_pgc;
        err = wbb_freeze(
            ptree, &pt_hdr, bld->pt_pgc + free_pgc(kblk), &pt_pgc, iov + iov_cnt, iov_max, &i);
        if (ev(err))
            goto errout;
        iov_cnt += i;
    }

    /* Format kblock header. */
    kblk->num_keys += ptree ? wbb_entries(ptree) : 0;
    _kblock_make_header(
        kblk, ptree, &wbt_hdr, &pt_hdr, pt_pgc, &blm_hdr, bld->seqno_min, bld->seqno_max, kblk->kblk_hdr);

    assert(iov_cnt <= iov_max);

    wlen = 0;
    for (i = 0; i < iov_cnt; i++)
        wlen += iov[i].iov_len;

    mclass = mclass_policy_get_type(mpolicy, bld->agegroup, HSE_MPOLICY_DTYPE_KEY);
    if (ev(mclass == HSE_MCLASS_INVALID)) {
        err = merr(EINVAL);
        goto errout;
    }

    err = mpool_mclass_props_get(bld->ds, mclass, &mc_props);
    if (ev(err))
        goto errout;

    kblocksz = mc_props.mc_mblocksz;
    if (wlen > kblocksz) {
        log_debug("BUG: wlen %lu kblocksz %lu", wlen, kblocksz);
        assert(wlen <= kblocksz);
        err = merr(EBUG);
        goto errout;
    }

    /* Set preallocate flag if this kblock's write length >= 90% of the mblock size */
    if (wlen >= ((kblocksz * 9) / 10))
        flags |= MPOOL_MBLOCK_PREALLOC;

    if (stats)
        tstart = get_time_ns();

    err = mpool_mblock_alloc(bld->ds, mclass, flags, &blkid, &mbprop);
    if (ev(err))
        goto errout;

    if (ev(mbprop.mpr_alloc_cap != kblocksz)) {
        assert(0);
        err = merr(EBUG);
        goto errout;
    }

    if (stats)
        count_ops(&stats->ms_kblk_alloc, 1, mbprop.mpr_alloc_cap, get_time_ns() - tstart);

    /* Write mblock in chunks.  Chunk size must be a multiple of
     * mblock optimal write size. Use largest chunk size less than 1 MiB.
     */
    chunk = 1024 * 1024;
    chunk = chunk - (chunk % mbprop.mpr_optimal_wrsz);
    err = mblk_blow_chunks(bld, blkid, iov, iov_cnt, chunk);
    if (ev(err))
        goto errout;

    err = blk_list_append(&bld->finished_kblks, blkid);
    if (ev(err))
        goto errout;

    /* unconditional reset */
    kblock_reset(kblk);
    free(iov);

    return 0;

errout:
    if (blkid)
        mpool_mblock_abort(bld->ds, blkid);
    free(iov);

    /* unconditional reset */
    kblock_reset(kblk);

    return err;
}

/*----------------------------------------------------------------
 * Kblock Builder
 */

/* Create a kblock builder */
merr_t
kbb_create(struct kblock_builder **builder_out, struct cn *cn, struct perfc_set *pc)
{
    merr_t                    err;
    struct kblock_builder *   bld;
    struct mpool_mclass_props props;
    struct mclass_policy *    policy;

    assert(builder_out);

    bld = calloc(1, sizeof(*bld));
    if (ev(!bld))
        return merr(ENOMEM);

    bld->cn = cn;

    bld->ds = cn_get_dataset(cn);
    bld->rp = cn_get_rp(cn);
    bld->cp = cn_get_cparams(cn);
    bld->pc = pc;
    bld->agegroup = HSE_MPOLICY_AGE_LEAF;

    policy = cn_get_mclass_policy(cn);

    err = mpool_mclass_props_get(
        bld->ds, policy->mc_table[bld->agegroup][HSE_MPOLICY_DTYPE_KEY], &props);
    if (ev(err))
        goto err_exit1;

    bld->max_size = props.mc_mblocksz;

    err = hlog_create(&bld->kvset_hlog, HLOG_PRECISION);
    if (ev(err))
        goto err_exit1;

    err = kblock_init(&bld->curr, bld->cp, bld->rp, bld->pc, bld->max_size);
    if (ev(err))
        goto err_exit2;

    err = wbb_create(&bld->ptree, bld->max_size / PAGE_SIZE, &bld->pt_pgc);
    if (ev(err))
        goto err_exit3;

    *builder_out = bld;
    return 0;

err_exit3:
    kblock_free(&bld->curr);

err_exit2:
    hlog_destroy(bld->kvset_hlog);

err_exit1:
    free(bld);
    return err;
}

/* Destroy a kblock builder. Must also abort any mblocks left behind. */
void
kbb_destroy(struct kblock_builder *bld)
{
    if (ev(!bld))
        return;

    hlog_destroy(bld->kvset_hlog);
    kblock_free(&bld->curr);
    wbb_destroy(bld->ptree);
    abort_mblocks(bld->ds, &bld->finished_kblks);
    blk_list_free(&bld->finished_kblks);
    free(bld);
}

merr_t
kbb_add_ptomb(
    struct kblock_builder *bld,
    const struct key_obj * kobj,
    const void *           kmd,
    uint                   kmd_len,
    struct kbb_key_stats * stats)
{
    merr_t err;
    bool   added = false;

    assert(stats->nptombs > 0);

    err = wbb_add_entry(
        bld->ptree,
        kobj,
        stats->nptombs,
        kmd,
        kmd_len,
        bld->curr.max_size / PAGE_SIZE,
        &bld->pt_pgc,
        &added);

    if (ev(err))
        return err;
    if (ev(!added))
        return merr(EXFULL);

    return 0;
}

/* Add a key with a vref to kblock. Create new kblock if needed. */
merr_t
kbb_add_entry(
    struct kblock_builder *bld,
    const struct key_obj * kobj,
    const void *           kmd,
    uint                   kmd_len,
    struct kbb_key_stats * stats)
{
    merr_t err;
    bool   added;
    u64    hash;

    assert(!bld->finished);
    assert(key_obj_len(kobj) > 0);
    assert(key_obj_len(kobj) <= HSE_KVS_KEY_LEN_MAX);
    assert(kmd_len);
    assert(stats->nvals);

    hash = hse_hash64v(kobj->ko_pfx, kobj->ko_pfx_len, kobj->ko_sfx, kobj->ko_sfx_len);

    err = kblock_add_entry(&bld->curr, kobj, kmd, kmd_len, stats, &added);
    if (ev(err))
        return err;
    if (added) {
        hlog_add(bld->kvset_hlog, hash);
        hlog_add(bld->curr.hlog, hash);
        return 0;
    }

    /* Key did not fit in current kblock.
     *   - bug if current kblock is empty
     *   - allocate and write current kblock to media
     *   - start new kblock
     *   - add key to new kblock
     *   - bug if fails with no space
     */
    assert(!kblock_is_empty(&bld->curr));
    if (ev(kblock_is_empty(&bld->curr)))
        return merr(EBUG);

    /* There are more keys to add, do not pass in ptree details */
    err = kblock_finish(bld, 0, bld->curr.hlog);
    if (ev(err))
        return err;

    err = kblock_add_entry(&bld->curr, kobj, kmd, kmd_len, stats, &added);
    if (ev(err))
        return err;
    hlog_add(bld->kvset_hlog, hash);
    hlog_add(bld->curr.hlog, hash);
    assert(added);
    if (ev(!added))
        return merr(EBUG);

    return 0;
}

/* Close out the current kblock, return IDs of all mblocks,
 * and mark the builder as closed for business.
 */
merr_t
kbb_finish(struct kblock_builder *bld, struct blk_list *kblks, u64 seqno_min, u64 seqno_max)
{
    merr_t err;
    bool   pt_kblock = true;

    if (ev(bld->finished))
        return merr(EINVAL);

    /* The only valid operation after finishing is destroy. Setting
     * this flag prevents other operations.
     */
    bld->finished = true;
    bld->seqno_min = seqno_min;
    bld->seqno_max = seqno_max;

    /* Must have a spot to keep the hlog */
    assert(bld->finished_kblks.n_blks == 0 || !kblock_is_empty(&bld->curr));

    /* Finish main wbtree. If there's enough space left in the kblock, add
     * ptree to this kblock. If not, add the ptree to the next kblock.
     */
    if (!kblock_is_empty(&bld->curr)) {
        struct wbb *pt = 0;
        uint64_t    kbsize = bld->max_size;
        uint64_t    ptsize = (wbb_page_cnt_get(bld->ptree)) * PAGE_SIZE;
        uint64_t    kbused =
            (KBLOCK_HDR_PAGES + HLOG_PGC + bld->curr.blm_pgc + wbb_page_cnt_get(bld->curr.wbtree)) *
            PAGE_SIZE;

        /* Write ptree here if we have enough space */
        if ((kbused + ptsize < kbsize)) {
            pt_kblock = false;
            pt = bld->ptree;
        }

        err = kblock_finish(bld, pt, bld->kvset_hlog);
        if (ev(err))
            return err;
    }

    if (wbb_entries(bld->ptree) && pt_kblock) {
        err = kblock_finish(bld, bld->ptree, bld->kvset_hlog);
        if (ev(err))
            return err;
    }

    /* Transfer ownership of blk_list and the mblocks in
     * the blk_list to caller
     */
    *kblks = bld->finished_kblks;
    memset(&bld->finished_kblks, 0, sizeof(bld->finished_kblks));

    return 0;
}

merr_t
kbb_set_agegroup(struct kblock_builder *bld, enum hse_mclass_policy_age age)
{
    merr_t                    err;
    struct mclass_policy *    policy;
    struct mpool_mclass_props props;

    bld->agegroup = age;

    policy = cn_get_mclass_policy(bld->cn);

    err = mpool_mclass_props_get(
        bld->ds, policy->mc_table[bld->agegroup][HSE_MPOLICY_DTYPE_KEY], &props);
    if (err)
        return err;

    bld->max_size = props.mc_mblocksz;

    return err;
}

enum hse_mclass_policy_age
kbb_get_agegroup(struct kblock_builder *bld)
{
    return bld->agegroup;
}

void
kbb_set_merge_stats(struct kblock_builder *bld, struct cn_merge_stats *stats)
{
    bld->mstats = stats;
}

/**
 * kblock_copy_range() - copy all keys `k' in range start < k <= end from @kbd
 *
 * @kbd:      kblock descriptor
 * @start:    start key (exclusive)
 * @end :     end key (inclusive)
 * @kbid_out: (output) output mblock ID where the keys are copied into.
 *
 * Notes:
 * (1) start == NULL implies a copy from the first key
 * (2) end == NULL implies a copy until EOF
 * (3) The output mblock in @kbid_out is not committed.
 *     It is left to the caller to either commit or abort it.
 */
static merr_t
kblock_copy_range(
    struct kblock_desc   *kbd,
    const struct key_obj *start, /* exclusive */
    const struct key_obj *end,   /* inclusive */
    uint64_t             *kbid_out)
{
    struct wbti *wbti = NULL;
    struct kblock_builder *kbb;
    struct key_obj cur = { 0 };
    const void *kmd;
    merr_t err;
    uint64_t tot_keys = 0;

    err = kbb_create(&kbb, kbd->cn, NULL);
    if (err)
        return err;

    if (start) {
        char kbuf[HSE_KVS_KEY_LEN_MAX];
        struct kvs_ktuple seek;
        uint klen;

        key_obj_copy(kbuf, sizeof(kbuf), &klen, start);
        kvs_ktuple_init_nohash(&seek, kbuf, klen);

        err = wbti_create(&wbti, kbd->kd_mbd, kbd->kd_wbd, &seek, false, false);
    } else {
        err = wbti_create(&wbti, kbd->kd_mbd, kbd->kd_wbd, NULL, false, false);
    }

    while (!err && wbti_next(wbti, &cur.ko_sfx, &cur.ko_sfx_len, &kmd)) {
        struct kbb_key_stats stats = { 0 };
        size_t off = 0, kmd_cnt_off;
        uint nvals;

        wbti_prefix(wbti, &cur.ko_pfx, &cur.ko_pfx_len);

        if (HSE_UNLIKELY(start && key_obj_cmp(&cur, start) == 0))
            continue;
        start = NULL;

        if (HSE_UNLIKELY(end && key_obj_cmp(&cur, end) > 0))
            break;

        nvals = stats.nvals = kmd_count(kmd, &off);
        kmd_cnt_off = off;

        while (nvals--) {
            struct kvs_vtuple_ref vref = { 0 };
            u64 vseq;

            wbt_read_kmd_vref(kmd, &off, &vseq, &vref);

            switch (vref.vr_type) {
            case vtype_val:
            case vtype_cval:
                stats.tot_vlen += (vref.vb.vr_complen ? : vref.vb.vr_len);
                break;

            case vtype_ival:
                stats.tot_vlen += vref.vi.vr_len;
                break;

            case vtype_tomb:
                ++stats.ntombs;
                break;

            case vtype_ptomb: /* TODO: must be an assert after ptomb is moved to a hblock */
            case vtype_zval:
                break;

            default:
                assert(0);
                break;
            }
        }

        err = kbb_add_entry(kbb, &cur, kmd + kmd_cnt_off, off - kmd_cnt_off, &stats);
        if (!err)
            ++tot_keys;
    }

    if (!err && tot_keys > 0) {
        struct blk_list kblk_list;

        err = kbb_finish(kbb, &kblk_list, 0, 0);
        if (!err) {
            assert(kblk_list.n_blks == 1);
            *kbid_out = kblk_list.blks->bk_blkid;
        }
    }

    wbti_destroy(wbti);
    kbb_destroy(kbb);

    return err;
}

merr_t
kblock_split(
    struct kblock_desc *kbd,
    struct key_obj     *split_key,
    uint64_t           *kbid_left,
    uint64_t           *kbid_right)
{
    merr_t err;

    INVARIANT(kbd && split_key && kbid_left && kbid_right);

    *kbid_left = *kbid_right = 0;

    err = kblock_copy_range(kbd, NULL, split_key, kbid_left);
    if (!err) {
        err = kblock_copy_range(kbd, split_key, NULL, kbid_right);
        if (!err && (*kbid_left == 0 && *kbid_right == 0)) {
            assert(*kbid_left || *kbid_right);
            err = merr(EBUG);
        }
    }

    return err;
}

#if HSE_MOCKING
#include "kblock_builder_ut_impl.i"
#endif /* HSE_MOCKING */
