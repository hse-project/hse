/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/logging/logging.h>
#include <hse/util/compression_lz4.h>
#include <hse/util/event_counter.h>
#include <hse/util/fmt.h>
#include <hse/util/keycmp.h>
#include <hse/util/page.h>
#include <hse/util/platform.h>
#include <hse/util/slab.h>
#include <hse/util/vlb.h>

#include <hse/kvdb_perfc.h>

#include <hse/ikvdb/c0.h>
#include <hse/ikvdb/lc.h>
#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/kvs.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/kvdb_ctxn.h>
#include <hse/ikvdb/kvdb_perfc.h>
#include <hse/ikvdb/tuple.h>
#include <hse/ikvdb/cursor.h>

#include <c0/c0_cursor.h>
#include "cn/cn_cursor.h"

/* clang-format off */

/*
 * Do not set any of these counters to a level less than three
 * otherwise it will defeat the optimization in ikvs_cursor_reset().
 */
struct perfc_name kvs_cc_perfc_op[] _dt_section = {
    NE(PERFC_RA_CC_HIT,             3, "Cursor cache hit/restore rate", "r_cc_hit(/s)"),
    NE(PERFC_RA_CC_MISS,            3, "Cursor cache miss/create rate", "r_cc_miss(/s)"),
    NE(PERFC_RA_CC_SAVEFAIL,        3, "Cursor cache save/fail rate",   "r_cc_savefail(/s)"),
    NE(PERFC_RA_CC_RESTFAIL,        3, "Cursor cache restore/fail",     "r_cc_restfail(/s)"),
    NE(PERFC_RA_CC_UPDATE,          3, "Cursor cache update rate",      "r_cc_update(/s)"),
    NE(PERFC_RA_CC_SAVE,            3, "Cursor cache save rate",        "r_cc_save(/s)"),

    NE(PERFC_BA_CC_INIT_CREATE_C0,  3, "c0 cursor init/create count",   "c_cc_c0_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_C0,  3, "c0 cursor init/update count",   "c_cc_c0_initupd"),
    NE(PERFC_BA_CC_INIT_CREATE_CN,  3, "cn cursor init/create count",   "c_cc_cn_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_CN,  3, "cn cursor init/update count",   "c_cc_cn_initupd"),
    NE(PERFC_BA_CC_UPDATED_C0,      3, "c0 cursor update count",        "c_cc_c0_update"),
    NE(PERFC_BA_CC_UPDATED_CN,      3, "cn cursor update count",        "c_cc_cn_update"),
};

NE_CHECK(kvs_cc_perfc_op, PERFC_EN_CC, "cursor cache perfc ops table/enum mismatch");

struct perfc_name kvs_cd_perfc_op[] _dt_section = {
    NE(PERFC_LT_CD_SAVE,            4, "cursor cache save latency",     "l_cc_save(ns)",    7),
    NE(PERFC_LT_CD_RESTORE,         4, "cursor cache restore latency",  "l_cc_restore(ns)", 7),

    NE(PERFC_LT_CD_CREATE_CN,       4, "cn cursor create latency",      "l_cc_create_cn", 7),
    NE(PERFC_LT_CD_UPDATE_CN,       4, "cn cursor update latency",      "l_cc_update_cn", 7),
    NE(PERFC_LT_CD_CREATE_C0,       4, "c0 cursor create latency",      "l_cc_create_c0", 7),
    NE(PERFC_LT_CD_UPDATE_C0,       4, "c0 cursor update latency",      "l_cc_update_c0", 7),

    NE(PERFC_DI_CD_READPERSEEK,     5, "Cursor reads per seek",         "d_cc_readperseek", 7),
    NE(PERFC_DI_CD_TOMBSPERPROBE,   5, "Tombs seen per pfx probe",      "d_cc_tombsperprobe", 7),
    NE(PERFC_DI_CD_ACTIVEKVSETS_CN, 3, "kvsets in cursors view",        "d_cc_activekvsets"),
};

NE_CHECK(kvs_cd_perfc_op, PERFC_EN_CD, "cursor dist perfc ops table/enum mismatch");

/*
 * Cursors freed by an app that are not too old and not in an error
 * state are saved into the cursor cache.
 *
 * Cached cursors may be retired completely after aging sufficiently.
 * Retiring a cursor is simply destroying the underlying object.
 *
 * The kvs_close path must release all cached cursors, but must
 * strip out the underlaying structures of active cursors, marking
 * the cursor with ESTALE.  This allows applications that have read
 * from a cursor to continue to use the key/value pointers in this
 * cursor after the kvs has been closed.
 */

/**
 * struct curcache_item - embedded in a cursor for cache management
 * @ci_ttl:   time (ns) beyond which cursor should be destroyed
 * @ci_key:   key that uniquely identifies the kvs and cursor type
 * @ci_next:  curcache_entry list linkage
 */
struct curcache_item {
    uint64_t                ci_ttl;
    uint64_t                ci_key;
    struct kvs_cursor_impl *ci_next;
};

/**
 * struct curcache_entry - rbtree entry with list of identical cursors
 * @ce_rbnode:  rb tree linkage
 * @ce_oldkey:  curcache comparator key of oldest cursor on %list
 * @ce_oldttl:  expiration time (ns) of oldest cursor on %list
 * @ce_list:    list of cached cursors (sorted by ttl)
 * @ce_next:    free list linkage (see cca_free)
 * @ce_cnt:     number of cursors on %list
 */
struct curcache_entry {
    struct rb_node          ce_rbnode;
    uint64_t                ce_oldkey;
    uint64_t                ce_oldttl;
    union {
        struct kvs_cursor_impl *ce_list;
        struct curcache_entry  *ce_next;
    };
    int                     ce_cnt;
};

/**
 * struct curcache - cursor cache bucket
 * @cb_lock:      lock to protect all fields in the bucket
 * @cb_entryc:    number of entries allocated from entryv[]
 * @cb_root:      root of the rb tree
 * @cb_evicted:   head of list of evicted entries
 * @cb_free:      head of list of free entries
 * @cb_active:    number of entries linked into the rb tree
 * @cb_prunec:    number of replaced entries queued for pruning
 * @cb_entrymax:  max entries in cca_entryv[]
 * @cb_entryv:    vector of curcache entries
 */
struct curcache_bucket {
    struct mutex            cb_lock HSE_ACP_ALIGNED;
    uint                    cb_entryc;

    struct rb_root          cb_root HSE_L1X_ALIGNED;
    struct kvs_cursor_impl *cb_evicted;
    struct curcache_entry  *cb_free;
    uint                    cb_active;
    uint                    cb_prunec;
    uint                    cb_entrymax;
    struct curcache_entry   cb_entryv[] HSE_ACP_ALIGNED;
};

#define KVS_CURSOR_SOURCES_CNT 3

struct kvs_cursor_impl {
    struct hse_kvs_cursor   kci_handle;
    struct curcache_item    kci_item;
    struct perfc_set *      kci_cc_pc;
    struct perfc_set *      kci_cd_pc;
    struct ikvs *           kci_kvs;
    struct c0_cursor *      kci_c0cur;
    struct lc_cursor *      kci_lccur;
    struct cn_cursor *      kci_cncur;
    struct element_source * kci_esrcv[KVS_CURSOR_SOURCES_CNT];
    struct bin_heap *       kci_bh;
    struct cursor_summary   kci_summary;

    /* current values for each cursor read */
    struct kvs_kvtuple kci_c0kv;
    struct kvs_kvtuple kci_cnkv;
    uint32_t           kci_limit_len;
    void *             kci_limit;

    struct kvs_cursor_element  kci_elem_last;
    struct kvs_cursor_element  kci_ptomb;
    struct key_obj             kci_last_kobj;
    struct key_obj *           kci_last;
    uint8_t *                       kci_last_kbuf;
    uint32_t                        kci_last_klen;

    uint32_t kci_eof : 1;
    uint32_t kci_need_toss : 1;
    uint32_t kci_need_seek : 1;
    uint32_t kci_reverse : 1;
    uint32_t kci_ptomb_set : 1;

    uint32_t kci_pfxlen;
    merr_t kci_err; /* bad cursor, must destroy */

    uint8_t  *kci_prefix;
    uint8_t   kci_buf[];
} HSE_L1D_ALIGNED;

static size_t kvs_cursor_impl_alloc_sz HSE_READ_MOSTLY;

static size_t               ikvs_curcachesz   HSE_READ_MOSTLY;
static void                *ikvs_curcachev    HSE_READ_MOSTLY;
static uint                 ikvs_curcachec    HSE_READ_MOSTLY;
static uint                 ikvs_colormax     HSE_READ_MOSTLY;

struct timer_list           ikvs_curcache_timer;
atomic_int                  ikvs_curcache_pruning;

/*-  Cursor Support  --------------------------------------------------*/

/*
 * ikvs cursors combine the separate c0, cN and Tx cursors.
 *
 * The underlying cursor reads copy their key and value internally,
 * returning pointers to them.  This allows the underlying strata
 * to change independent of its present iterator position.  This also
 * allows pointers to the cached information to be used without further
 * copies.
 *
 * Thus, each underlying cursor has state:
 *      we either have a cached value (ready)
 *      or we are at eof (eof)
 *      or we need to attempt to read (!ready && !eof)
 *
 * If the ikvs cursor encounters an error from the underlying cursor,
 * the only way to recover is to destroy the ikvs cursor and create another.
 * In particular, update does NOT clear the error state, and no effort is
 * made to attempt to recover a partial cursor.
 */

#define cursor_h2r(_h)      container_of(_h, struct kvs_cursor_impl, kci_handle)

/* clang-format on */

/**
 * ikvs_curcache_entry_alloc() - allocate a cursor cache entry
 * @bkt:  cursor cache bucket
 *
 * Caller must hold the cursor cache lock.
 */
static struct curcache_entry *
ikvs_curcache_entry_alloc(struct curcache_bucket *bkt)
{
    struct curcache_entry *entry;

    entry = bkt->cb_free;
    if (entry) {
        bkt->cb_free = entry->ce_next;
        return entry;
    }

    if (bkt->cb_entryc < bkt->cb_entrymax) {
        entry = bkt->cb_entryv + bkt->cb_entryc++;
        memset(entry, 0, sizeof(*entry));
    }

    return entry;
}

/**
 * ikvs_cursor_bkt_free() - free a cursor cache entry
 * @bkt:    cursor cache bucket
 * @entry:  entry to free
 *
 * Caller must hold the cursor cache lock.
 */
static void
ikvs_curcache_entry_free(struct curcache_bucket *bkt, struct curcache_entry *entry)
{
    entry->ce_next = bkt->cb_free;
    bkt->cb_free = entry;
}

static HSE_ALWAYS_INLINE size_t
ikvs_curcache_idx2bktoff(uint idx)
{
    size_t offset;

    idx %= ikvs_curcachec;

    offset = ikvs_curcachesz * idx;
    offset += sizeof(struct curcache_bucket) * (idx % ikvs_colormax);

    return offset;
}

static HSE_ALWAYS_INLINE struct curcache_bucket *
ikvs_curcache_td2bkt(void)
{
    static thread_local size_t tls_offset;

    if (HSE_UNLIKELY(!tls_offset)) {
        static atomic_uint g_cc_idx;

        tls_offset = ikvs_curcache_idx2bktoff(atomic_inc_return(&g_cc_idx));
    }

    return ikvs_curcachev + tls_offset;
}

/**
 * ikvs_curcache_prune() - prune all expired cursors matching the given %kvs
 * @bkt:       cursor cache bucket ptr
 * @kvs:       %kvs to match (or NULL to match all)
 * @now:       evict cursors where %now exceeds their time-to-live
 * @retiredp:  ptr to count of cursors retired
 * @evictedp:  ptr to count of cursors evicted
 */
static void
ikvs_curcache_prune_impl(
    struct curcache_bucket *bkt,
    struct ikvs *           kvs,
    uint64_t                now,
    uint *                  retiredp,
    uint *                  evictedp)
{
    struct kvs_cursor_impl *evicted, *old;
    struct rb_node *        node;
    uint                    ndestroyed = 0;
    uint                    nretired = 0;

    mutex_lock(&bkt->cb_lock);
    node = rb_first(&bkt->cb_root);
    evicted = bkt->cb_evicted;
    bkt->cb_evicted = NULL;

    while (node) {
        struct curcache_entry *entry = rb_entry(node, typeof(*entry), ce_rbnode);

        node = rb_next(node);

        if (now < entry->ce_oldttl)
            continue;

        if (kvs && kvs != entry->ce_list->kci_kvs)
            continue;

        while (NULL != (old = entry->ce_list)) {
            if (old->kci_item.ci_ttl > now)
                break;

            entry->ce_list = old->kci_item.ci_next;
            old->kci_item.ci_next = evicted;
            evicted = old;
            --entry->ce_cnt;
            ++nretired;
        }

        if (old) {
            entry->ce_oldkey = old->kci_item.ci_key;
            entry->ce_oldttl = old->kci_item.ci_ttl;
        } else {
            rb_erase(&entry->ce_rbnode, &bkt->cb_root);
            ikvs_curcache_entry_free(bkt, entry);
        }
    }

    /* Cursors on the evicted list have already been accounted for...
     */
    bkt->cb_active -= nretired;
    bkt->cb_prunec = 0;
    mutex_unlock(&bkt->cb_lock);

    while (NULL != (old = evicted)) {
        evicted = old->kci_item.ci_next;
        kvs_cursor_destroy(&old->kci_handle);
        ++ndestroyed;
    }

    *evictedp += ndestroyed - nretired;
    *retiredp += nretired;
}

static void
ikvs_curcache_prune(struct ikvs *kvs)
{
    uint nretired = 0, nevicted = 0, i;

    atomic_inc_acq(&ikvs_curcache_pruning);

    for (i = 0; i < ikvs_curcachec; ++i) {
        struct curcache_bucket *bkt = ikvs_curcachev + ikvs_curcache_idx2bktoff(i);

        ikvs_curcache_prune_impl(bkt, kvs, kvs ? UINT64_MAX : jclock_ns, &nretired, &nevicted);
    }

    atomic_dec_rel(&ikvs_curcache_pruning);

    if (nretired > 0)
        perfc_add(&kvdb_metrics_pc, PERFC_RA_KVDBMETRICS_CURRETIRED, nretired);

    if (nevicted > 0)
        perfc_add(&kvdb_metrics_pc, PERFC_RA_KVDBMETRICS_CUREVICTED, nevicted);
}

static void
ikvs_curcache_timer_cb(ulong arg)
{
    ikvs_curcache_timer.expires = nsecs_to_jiffies(jclock_ns + NSEC_PER_SEC / 3);

    ikvs_curcache_prune(NULL);

    add_timer(&ikvs_curcache_timer);
}

/* ikvs_curcache_key() constructs a key for the cursor cache comparator
 * such that we can compare the kvs and distinguishing cursor attributes
 * in just one comparison.  This reduces the number of cursor objects
 * we have to touch while walking the tree.
 */
static HSE_ALWAYS_INLINE uint64_t
ikvs_curcache_key(const uint64_t gen, const bool reverse)
{
    return (gen << 63) | reverse;
}

static HSE_ALWAYS_INLINE int
ikvs_curcache_cmp(struct curcache_entry *entry, uint64_t key, const void *prefix, size_t pfxlen)
{
    if (key != entry->ce_oldkey)
        return (key < entry->ce_oldkey) ? -1 : 1;

    if (!prefix)
        return 0;

    return keycmp(prefix, pfxlen, entry->ce_list->kci_prefix, entry->ce_list->kci_pfxlen);
}

static struct kvs_cursor_impl *
ikvs_curcache_insert(struct curcache_bucket *bkt, struct kvs_cursor_impl *cur)
{
    struct curcache_entry *entry;
    struct rb_node **      link, *parent;
    uint64_t               key;
    size_t                 pfxlen;
    void *                 prefix;
    int                    rc;

    key = cur->kci_item.ci_key;
    prefix = cur->kci_prefix;
    pfxlen = cur->kci_pfxlen;

    mutex_lock(&bkt->cb_lock);
    link = &bkt->cb_root.rb_node;
    parent = NULL;
    entry = NULL;

    while (*link) {
        parent = *link;
        entry = rb_entry(parent, typeof(*entry), ce_rbnode);

        rc = ikvs_curcache_cmp(entry, key, prefix, pfxlen);

        if (rc == 0)
            break;

        link = (rc < 0) ? &parent->rb_left : &parent->rb_right;
    }

    if (*link) {
        struct kvs_cursor_impl **pp = &entry->ce_list;

        /* The list of cursors is sorted oldest-to-youngest from head-to-tail
         * to reduce unnecessary retirements (because ikvs_curcache_remove()
         * always removes the oldest cursor from a given list).
         */
        while (1) {
            struct kvs_cursor_impl *old = *pp;

            if (!old || cur->kci_item.ci_ttl < old->kci_item.ci_ttl) {
                cur->kci_item.ci_next = old;
                bkt->cb_active++;
                *pp = cur;
                cur = NULL;
                break;
            }

            pp = &old->kci_item.ci_next;
        }

        if (++entry->ce_cnt > 64 || bkt->cb_active > bkt->cb_entrymax) {
            cur = entry->ce_list;
            entry->ce_list = cur->kci_item.ci_next;
            pp = &entry->ce_list;

            bkt->cb_active--;
            --entry->ce_cnt;

            if (bkt->cb_active + bkt->cb_prunec < ((bkt->cb_entrymax * 9) / 10)) {
                cur->kci_item.ci_next = bkt->cb_evicted;
                bkt->cb_evicted = cur;
                bkt->cb_prunec++;
                cur = NULL;
            }
        }

        if (&entry->ce_list == pp) {
            entry->ce_oldkey = entry->ce_list->kci_item.ci_key;
            entry->ce_oldttl = entry->ce_list->kci_item.ci_ttl;
        }
    } else {
        entry = ikvs_curcache_entry_alloc(bkt);
        if (entry) {
            entry->ce_oldkey = cur->kci_item.ci_key;
            entry->ce_oldttl = cur->kci_item.ci_ttl;
            entry->ce_list = cur;
            entry->ce_cnt = 1;

            rb_link_node(&entry->ce_rbnode, parent, link);
            rb_insert_color(&entry->ce_rbnode, &bkt->cb_root);

            cur->kci_item.ci_next = NULL;
            bkt->cb_active++;
            cur = NULL;
        }
    }
    mutex_unlock(&bkt->cb_lock);

    return cur;
}

static struct kvs_cursor_impl *
ikvs_curcache_remove(struct curcache_bucket *bkt, uint64_t key, const void *prefix, size_t pfx_len)
{
    struct kvs_cursor_impl *old;
    struct curcache_entry * entry;
    struct rb_node *        node;
    int                     rc;

    mutex_lock(&bkt->cb_lock);
    node = bkt->cb_root.rb_node;
    old = NULL;
    entry = NULL;

    while (node) {
        entry = rb_entry(node, typeof(*entry), ce_rbnode);

        rc = ikvs_curcache_cmp(entry, key, prefix, pfx_len);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            break;
    }

    if (node) {
        old = entry->ce_list;
        entry->ce_list = old->kci_item.ci_next;
        bkt->cb_active--;

        if (--entry->ce_cnt == 0) {
            rb_erase(node, &bkt->cb_root);
            ikvs_curcache_entry_free(bkt, entry);
        } else {
            entry->ce_oldkey = entry->ce_list->kci_item.ci_key;
            entry->ce_oldttl = entry->ce_list->kci_item.ci_ttl;
        }
    }
    mutex_unlock(&bkt->cb_lock);

    return old;
}

/* Prune from the cursor cache all cursors related to the given kvs.
 * This function is called by kvs_close() to purge the cache of all
 * cursors bound to the given kvs.
 */
void
kvs_cursor_reap(struct ikvs *kvs)
{
    ikvs_curcache_prune(kvs);

    /* Wait for the async pruner in case we ran concurrently...
     */
    while (atomic_read(&ikvs_curcache_pruning) > 0)
        usleep(333);
}

static void
ikvs_cursor_reset(struct kvs_cursor_impl *cursor)
{
    struct ikvs *kvs = cursor->kci_kvs;

    cursor->kci_need_seek = 0;
    cursor->kci_need_toss = 1;
    cursor->kci_eof = 0;
    cursor->kci_ptomb_set = 0;
    cursor->kci_summary.addr = NULL;

    cursor->kci_cc_pc = PERFC_ISON(&kvs->ikv_cc_pc) ? &kvs->ikv_cc_pc : NULL;
    cursor->kci_cd_pc = PERFC_ISON(&kvs->ikv_cd_pc) ? &kvs->ikv_cd_pc : NULL;

    cursor->kci_item.ci_ttl = jclock_ns + kvs->ikv_rp.kvs_cursor_ttl * USEC_PER_SEC;
}

static struct kvs_cursor_impl *
ikvs_cursor_restore(struct ikvs *kvs, const void *prefix, size_t pfx_len, bool reverse)
{
    struct kvs_cursor_impl *cur;
    uint64_t                key, tstart;

    tstart = perfc_lat_startl(&kvs->ikv_cd_pc, PERFC_LT_CD_RESTORE);

    key = ikvs_curcache_key(kvs->ikv_gen, reverse);

    cur = ikvs_curcache_remove(ikvs_curcache_td2bkt(), key, prefix, pfx_len);
    if (!cur) {
        PERFC_INC_RU(&kvs->ikv_cc_pc, PERFC_RA_CC_MISS);
        return NULL;
    }

    perfc_lat_record(&kvs->ikv_cd_pc, PERFC_LT_CD_RESTORE, tstart);
    PERFC_INC_RU(&kvs->ikv_cc_pc, PERFC_RA_CC_HIT);

    return cur;
}

/**
 * ikvs_cursor_save() - save a cursor to the cursor cache
 * @cur:  the cursor to save
 *
 * Saves the given cursor to the cursor cache if it's not too old,
 * and otherwise fully destroys it.
 *
 * Set the kvs rparam kvs_cursor_ttl to zero to disable caching.
 *
 * We only cache short-lived cursors because long-lived cursors
 * have pinned resources that we need to release as soon as
 * possible (e.g., refs on c0 kvmultisets and cn kvsets).
 *
 * [HSE_REVISIT] We could cache long-lived cursors if we can
 * inexpensively determine that both c0 and cn haven't mutated
 * since the cursor was acquired (e.g., a read-mostly workload).
 */
static void
ikvs_cursor_save(struct kvs_cursor_impl *cur)
{
    struct ikvs *kvs = cur->kci_kvs;
    uint64_t     tstart;

#ifndef HSE_BUILD_RELEASE
    perfc_dis_record(cur->kci_cd_pc, PERFC_DI_CD_READPERSEEK, cur->kci_summary.util);
    cur->kci_summary.util = 0;
#endif

    tstart = perfc_lat_startl(&kvs->ikv_cd_pc, PERFC_LT_CD_SAVE);

    if (cur->kci_item.ci_ttl > jclock_ns)
        cur = ikvs_curcache_insert(ikvs_curcache_td2bkt(), cur);

    if (cur) {
        perfc_inc(&kvs->ikv_cc_pc, PERFC_RA_CC_SAVEFAIL);
        kvs_cursor_destroy(&cur->kci_handle);
    } else {
        perfc_lat_record(&kvs->ikv_cd_pc, PERFC_LT_CD_SAVE, tstart);
        PERFC_INC_RU(&kvs->ikv_cc_pc, PERFC_RA_CC_SAVE);
    }
}

struct hse_kvs_cursor *
kvs_cursor_alloc(struct ikvs *kvs, const void *prefix, size_t pfx_len, bool reverse)
{
    struct kvs_cursor_impl *cur;

    cur = ikvs_cursor_restore(kvs, prefix, pfx_len, reverse);
    if (cur) {

        /*
         * A cached cursor's state must be reset.
         * To avoid a redundant seek, set the seek flag:
         * if read is next operation, must seek to start,
         * else if seek is done, already at correct location
         */
        ikvs_cursor_reset(cur);
        return &cur->kci_handle;
    }

    cur = vlb_alloc(kvs_cursor_impl_alloc_sz);
    if (ev(!cur))
        return NULL;

    memset(cur, 0, sizeof(*cur));

    cur->kci_item.ci_key = ikvs_curcache_key(kvs->ikv_gen, reverse);
    cur->kci_cc_pc = PERFC_ISON(&kvs->ikv_cc_pc) ? &kvs->ikv_cc_pc : NULL;
    cur->kci_cd_pc = PERFC_ISON(&kvs->ikv_cd_pc) ? &kvs->ikv_cd_pc : NULL;
    cur->kci_kvs = kvs;
    cur->kci_pfxlen = pfx_len;

    /* Point buffer-pointers to the right memory regions */
    cur->kci_prefix = cur->kci_buf + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX;
    cur->kci_last_kbuf = cur->kci_prefix + HSE_KVS_KEY_LEN_MAX;
    cur->kci_limit = cur->kci_last_kbuf + HSE_KVS_KEY_LEN_MAX;

    if (prefix)
        memcpy(cur->kci_prefix, prefix, pfx_len);

    cur->kci_limit_len = 0;
    cur->kci_handle.kc_filter.kcf_maxkey = 0;

    cur->kci_reverse = reverse;
    ikvs_cursor_reset(cur);

    /* Pad with 0xff to make reverse cursor seek-to-pfx simple */
    if (reverse)
        memset(cur->kci_prefix + pfx_len, 0xFF, HSE_KVS_KEY_LEN_MAX - pfx_len);

    return &cur->kci_handle;
}

void
kvs_cursor_free(struct hse_kvs_cursor *cursor)
{
    if (cursor->kc_err)
        kvs_cursor_destroy(cursor);
    else
        ikvs_cursor_save(cursor_h2r(cursor));
}

static merr_t
kvs_cursor_bh_create(struct hse_kvs_cursor *cursor)
{
    struct kvs_cursor_impl *cur = cursor_h2r(cursor);
    bin_heap_compare_fn *cmp;
    merr_t err;

    cur->kci_esrcv[0] = c0_cursor_es_make(cur->kci_c0cur);
    cur->kci_esrcv[1] = lc_cursor_es_make(cur->kci_lccur);
    cur->kci_esrcv[2] = cn_cursor_es_make(cur->kci_cncur);

    cmp = cur->kci_reverse ? kvs_cursor_cmp_rev : kvs_cursor_cmp;
    if (cur->kci_bh)
        bin_heap_destroy(cur->kci_bh);

    err = bin_heap_create(KVS_CURSOR_SOURCES_CNT, cmp, &cur->kci_bh);
    if (ev(err))
        return err;

    return 0;
}

merr_t
kvs_cursor_init(struct hse_kvs_cursor *cursor, struct kvdb_ctxn *ctxn)
{
    struct kvs_cursor_impl *cur = cursor_h2r(cursor);
    struct ikvs *           kvs = cur->kci_kvs;
    void *                  c0 = kvs->ikv_c0;
    void *                  lc = kvs->ikv_lc;
    void *                  cn = kvs->ikv_cn;
    uint64_t                seqno = cursor->kc_seq;
    merr_t                  err = 0;
    uint64_t                tstart;
    struct cursor_summary * summary = &cur->kci_summary;
    bool                    reverse = cur->kci_reverse;
    const void *            prefix = cur->kci_prefix;
    size_t                  pfxlen = cur->kci_pfxlen;

    /* no context: update must seek to beginning */
    cur->kci_last = 0;

#ifndef HSE_BUILD_RELEASE
    if (perfc_ison(cur->kci_cd_pc, PERFC_DI_CD_READPERSEEK)) {
        memset(summary, 0, sizeof(*summary));
        summary->addr = cur;
        summary->seqno = seqno;
        summary->created = get_time_ns();
    }
#endif

    /* Create/Update c0 cursor */
    if (!cur->kci_c0cur) {

        assert(!cur->kci_cncur);

        /* Create c0 cursor */
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_CREATE_C0);
        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_CREATE_C0);
        err = c0_cursor_create(c0, seqno, reverse, prefix, pfxlen, summary, &cur->kci_c0cur);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_CREATE_C0, tstart);
    } else {
        uint32_t flags = 0;

        assert(cur->kci_cncur);

        /* Update c0 cursor */
        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_C0);

        /* [HSE_REVISIT] mapi breaks initialization of flags.
         */
        err = c0_cursor_update(cur->kci_c0cur, seqno, &flags);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

        if (flags & CURSOR_FLAG_SEQNO_CHANGE)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_UPDATE_C0);
    }

    if (ev(err))
        goto error;

    assert(cur->kci_c0cur);

    if (!cur->kci_lccur) {
        uint16_t skidx = c0_index(c0);
        int32_t  tree_pfxlen = c0_get_pfx_len(c0);
        uintptr_t seqnoref = ctxn ? kvdb_ctxn_get_seqnoref(ctxn) : 0;

        err = lc_cursor_create(
            lc,
            skidx,
            seqno,
            seqnoref,
            reverse,
            prefix,
            pfxlen,
            tree_pfxlen,
            summary,
            &cur->kci_lccur);
    } else {
        err = lc_cursor_update(cur->kci_lccur, prefix, pfxlen, seqno);
    }

    if (ev(err))
        goto error;

    if (!cur->kci_cncur) {
        /* Create cn cursor */
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_CREATE_CN);
        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_CREATE_CN);
        err = cn_cursor_create(cn, seqno, reverse, prefix, pfxlen, summary, &cur->kci_cncur);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_CREATE_CN, tstart);
    } else {
        bool updated = false;

        /* Update cn cursor */
        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_CN);

        /* [HSE_REVISIT] mapi breaks initialization of updated.
         */
        err = cn_cursor_update(cur->kci_cncur, seqno, &updated);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_CN, tstart);

        if (updated)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_UPDATE_CN);
    }

    if (ev(err))
        goto error;

    assert(cur->kci_cncur);

    cur->kci_need_toss = 0;
    cur->kci_need_seek = 1;

    memcpy(cur->kci_last_kbuf, cur->kci_prefix, cur->kci_pfxlen);
    cur->kci_last_klen = cur->kci_pfxlen;
    if (cur->kci_reverse) {
        cur->kci_last_klen = HSE_KVS_KEY_LEN_MAX;
        memset(cur->kci_last_kbuf + cur->kci_pfxlen, 0xFF, HSE_KVS_KEY_LEN_MAX - cur->kci_pfxlen);
    }

    if (cursor->kc_bind)
        c0_cursor_bind_txn(cur->kci_c0cur, ctxn);

    err = kvs_cursor_bh_create(cursor);

error:
    cursor->kc_err = err;
    return err;
}

merr_t
kvs_cursor_bind_txn(struct hse_kvs_cursor *handle, struct kvdb_ctxn *ctxn)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (ev(!cursor->kci_c0cur))
        return merr(ENXIO);

    c0_cursor_bind_txn(cursor->kci_c0cur, ctxn);

    return 0;
}

void
kvs_cursor_destroy(struct hse_kvs_cursor *handle)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (handle->kc_bind)
        kvdb_ctxn_cursor_unbind(handle->kc_bind);
    if (cursor->kci_c0cur)
        c0_cursor_destroy(cursor->kci_c0cur);
    if (cursor->kci_lccur)
        lc_cursor_destroy(cursor->kci_lccur);
    if (cursor->kci_cncur)
        cn_cursor_destroy(cursor->kci_cncur);

    if (cursor->kci_bh)
        bin_heap_destroy(cursor->kci_bh);

    vlb_free(cursor, kvs_cursor_impl_alloc_sz);
}

merr_t
kvs_cursor_update(struct hse_kvs_cursor *handle, struct kvdb_ctxn *ctxn, uint64_t seqno)
{
    struct kvs_cursor_impl *cursor = (void *)handle;
    struct kvdb_ctxn_bind * bind = handle->kc_bind;
    uint32_t                flags;
    bool                    updated;
    uint64_t                tstart;

    assert(seqno == handle->kc_seq);

    perfc_inc(cursor->kci_cc_pc, PERFC_RA_CC_UPDATE);

#ifndef HSE_BUILD_RELEASE
    if (cursor->kci_summary.addr) {
        ++cursor->kci_summary.n_update;
        cursor->kci_summary.seqno = seqno;
        cursor->kci_summary.updated = get_time_ns();

        perfc_dis_record(cursor->kci_cd_pc, PERFC_DI_CD_READPERSEEK, cursor->kci_summary.util);
        cursor->kci_summary.util = 0;
    }
#endif

    if (bind)
        handle->kc_gen = atomic_read(&bind->b_gen);

    /* Copy out last key that was read */
    if (cursor->kci_last) {
        key_obj_copy(
            cursor->kci_last_kbuf, HSE_KVS_KEY_LEN_MAX, &cursor->kci_last_klen, cursor->kci_last);
    } else {
        cursor->kci_need_toss = 0;
        cursor->kci_last_klen = cursor->kci_reverse ? HSE_KVS_KEY_LEN_MAX : cursor->kci_pfxlen;
        memcpy(cursor->kci_last_kbuf, cursor->kci_prefix, cursor->kci_last_klen);
    }

    /* Update c0 cursor */
    tstart = perfc_lat_startu(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_C0);

    cursor->kci_err = c0_cursor_update(cursor->kci_c0cur, seqno, &flags);
    if (ev(cursor->kci_err))
        return cursor->kci_err;
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

    if (flags & CURSOR_FLAG_SEQNO_CHANGE)
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_C0);

    /* Update lc cursor */
    cursor->kci_err =
        lc_cursor_update(cursor->kci_lccur, cursor->kci_last_kbuf, cursor->kci_last_klen, seqno);
    if (ev(cursor->kci_err))
        return cursor->kci_err;

    /* Update cn cursor */
    tstart = perfc_lat_startu(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_CN);

    cursor->kci_err = cn_cursor_update(cursor->kci_cncur, seqno, &updated);
    if (ev(cursor->kci_err))
        return cursor->kci_err;
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_CN, tstart);

    if (updated) {
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_CN);

        if (perfc_ison(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN)) {
            uint32_t active = 0, total;

            /* [HSE_REVISIT] mapi breaks initialization of active by
             * cn_cursor_active_kvsets(), so we have to do it here.
             */
            cn_cursor_active_kvsets(cursor->kci_cncur, &active, &total);
            perfc_dis_record(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);
        }
    }

    /* Seek will re-prepare the binheap. */
    cursor->kci_need_seek = 1;

    /* Reset the ptomb_set flag to discard an old ptomb (which may have been ingested/compacted
     * since). The following seek will set it if needed.
     */
    cursor->kci_ptomb_set = 0;

    if (handle->kc_bind)
        c0_cursor_bind_txn(cursor->kci_c0cur, ctxn);

    return 0;
}

static bool
ikvs_cursor_should_drop(struct kvs_cursor_element *item, struct kvs_cursor_element *pt)
{
    uint64_t                  pt_seqno = 0, elem_seqno = 0;
    enum hse_seqno_state pt_state, elem_state;

    pt_state = seqnoref_to_seqno(pt->kce_seqnoref, &pt_seqno);
    elem_state = seqnoref_to_seqno(item->kce_seqnoref, &elem_seqno);

    if (pt_state == HSE_SQNREF_STATE_UNDEFINED) {
        if (elem_state == HSE_SQNREF_STATE_UNDEFINED) {
            /* If item and pt are from active txns, they must belong to the same txn. */
            assert(pt->kce_seqnoref == item->kce_seqnoref);
            return false;
        }

        /* item is in defined state and ptomb is from txn, skip item */

    } else {
        assert(pt_state == HSE_SQNREF_STATE_DEFINED);
        if (elem_state == HSE_SQNREF_STATE_UNDEFINED)
            return false;

        if (pt_seqno <= elem_seqno)
            return false;
    }

    return true;
}

merr_t
ikvs_cursor_replenish(struct kvs_cursor_impl *cursor)
{
    bool                       is_ptomb, is_tomb;
    merr_t                     err = 0;
    struct kvs_cursor_element *item, *popme;

    if (cursor->kci_eof)
        return 0;

    do {
        cursor->kci_eof = !bin_heap_peek(cursor->kci_bh, (void **)&item);

        if (cursor->kci_eof)
            goto out;

        cursor->kci_elem_last = *item;
        cursor->kci_last_kobj = item->kce_kobj;
        cursor->kci_last = &cursor->kci_last_kobj;

        /* is_tomb is true when item is a reg tomb or a ptomb */
        is_tomb = HSE_CORE_IS_TOMB(item->kce_vt.vt_data);
        is_ptomb = HSE_CORE_IS_PTOMB(item->kce_vt.vt_data);

        /* discard current kv-tuple */
        bin_heap_pop(cursor->kci_bh, (void **)&popme);

        if (cursor->kci_ptomb_set) {
            int rc;

            rc = key_obj_cmp_prefix(&cursor->kci_ptomb.kce_kobj, &cursor->kci_last_kobj);
            if (rc == 0) {
                if (ikvs_cursor_should_drop(&cursor->kci_elem_last, &cursor->kci_ptomb)) {
                    is_tomb = true;
                    continue;
                }
            } else {
                cursor->kci_ptomb_set = 0;
            }
        }

        if (is_ptomb) {
            cursor->kci_ptomb = cursor->kci_elem_last;
            cursor->kci_ptomb_set = 1;
        } else {
            /* drop dups */
            while (bin_heap_peek(cursor->kci_bh, (void **)&item)) {
                if (key_obj_cmp(&item->kce_kobj, cursor->kci_last))
                    break; /* not a dup */

                bin_heap_pop(cursor->kci_bh, (void **)&popme);
            }
        }
    } while (is_ptomb || is_tomb);

out:
    return err;
}

static merr_t
ikvs_cursor_seek(struct kvs_cursor_impl *cursor, const void *key, size_t klen)
{
    struct hse_kvs_cursor *handle = &cursor->kci_handle;
    struct kc_filter *     filt = handle->kc_filter.kcf_maxkey ? &handle->kc_filter : 0;
    merr_t                 err = 0;
    int                    cnt;

    cursor->kci_eof = 0;

    err = c0_cursor_seek(cursor->kci_c0cur, key, klen, filt);
    if (ev(err))
        goto out;

    err = lc_cursor_seek(cursor->kci_lccur, key, klen, filt);
    if (ev(err))
        goto out;

    err = cn_cursor_seek(cursor->kci_cncur, key, klen, filt);
    if (ev(err))
        goto out;

    cnt = 0;
    cursor->kci_esrcv[cnt++] = c0_cursor_es_get(cursor->kci_c0cur);
    cursor->kci_esrcv[cnt++] = lc_cursor_es_get(cursor->kci_lccur);
    cursor->kci_esrcv[cnt++] = cn_cursor_es_get(cursor->kci_cncur);

    err = bin_heap_prepare(cursor->kci_bh, cnt, cursor->kci_esrcv);

    if (perfc_ison(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN)) {
        uint32_t active = 0, total;

        /* [HSE_REVISIT] mapi breaks initialization of active by
         * cn_cursor_active_kvsets(), so we have to do it here.
         */
        cn_cursor_active_kvsets(cursor->kci_cncur, &active, &total);
        perfc_dis_record(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);
    }

out:
    return err;
}

void
kvs_cursor_key_copy(
    struct hse_kvs_cursor  *cursor,
    void                   *buf,
    size_t                  bufsz,
    const void            **key_out,
    size_t                 *klen_out)
{
    struct kvs_cursor_impl *cur = cursor_h2r(cursor);
    uint                    klen;
    void                   *key;

    if (!buf) {
        buf = cur->kci_buf;
        bufsz = HSE_KVS_KEY_LEN_MAX;
    }

    key = key_obj_copy(buf, bufsz, &klen, cur->kci_last);

    if (klen_out)
        *klen_out = klen;

    if (key_out)
        *key_out = key;
}

merr_t
kvs_cursor_val_copy(
    struct hse_kvs_cursor *cursor,
    void *buf,
    size_t bufsz,
    const void **val_out,
    size_t *vlen_out)
{
    struct kvs_cursor_impl *cur;
    struct kvs_vtuple *vt;
    uint clen;
    merr_t err = 0;

    if (!cursor)
        return merr(EINVAL);

    cur = cursor_h2r(cursor);

    vt = &cur->kci_elem_last.kce_vt;
    clen = cur->kci_elem_last.kce_complen;

    if (!buf && !val_out)
        goto out;

    if (!buf) {
        buf = cur->kci_buf + HSE_KVS_KEY_LEN_MAX;
        bufsz = HSE_KVS_VALUE_LEN_MAX;
    }

    if (clen) {
        uint outlen;

        err = compress_lz4_ops.cop_decompress(vt->vt_data, clen, buf, bufsz, &outlen);
        if (ev(err))
            return err;

        if (ev(outlen != min_t(uint64_t, kvs_vtuple_vlen(vt), bufsz)))
            return merr(EBUG);

    } else {
        memcpy(buf, vt->vt_data, min_t(uint64_t, kvs_vtuple_vlen(vt), bufsz));
    }

    if (val_out)
        *val_out = buf;

out:
    if (vlen_out)
        *vlen_out = kvs_vtuple_vlen(vt);

    return 0;
}

merr_t
kvs_cursor_read(struct hse_kvs_cursor *handle, unsigned int flags, bool *eofp)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (ev(cursor->kci_err))
        return cursor->kci_err;

    if (cursor->kci_need_seek) {
        struct kvs_ktuple key = { 0 };
        bool              toss = cursor->kci_need_toss;

        cursor->kci_err = kvs_cursor_seek(
            &cursor->kci_handle, cursor->kci_last_kbuf, cursor->kci_last_klen, 0, 0, &key);

        if (ev(cursor->kci_err))
            return cursor->kci_err;

        *eofp = cursor->kci_eof;
        if (*eofp)
            return 0;

        /* The need_seek flag is set only if the last operation was either a create or an
         * update.
         *
         * The need_toss flag is set only for the order of operations: [read, update, read]
         * The need_toss flag is not set for:
         *  1. [seek, update, read]: Here the key we seek-ed to was never read
         *  2. [create, read]: Here we've yet to position at prefix
         *
         *  In addition to the order of operations, it's also important to check whether
         *  the key still exists and has not been deleted since the last update/create.
         */

        if (toss) {
            struct key_obj ko;

            key2kobj(&ko, cursor->kci_last_kbuf, cursor->kci_last_klen);
            if (toss && !key_obj_cmp(&ko, cursor->kci_last)) {
                cursor->kci_err = ikvs_cursor_replenish(cursor);
                if (ev(cursor->kci_err))
                    return cursor->kci_err;
            }
        }

    } else {
        if (cursor->kci_need_toss || !cursor->kci_last) {
            cursor->kci_err = ikvs_cursor_replenish(cursor);
            if (ev(cursor->kci_err))
                return cursor->kci_err;
        }
    }

    cursor->kci_need_toss = 1;
    *eofp = cursor->kci_eof;
    if (*eofp)
        return 0;

    return cursor->kci_err;
}

merr_t
kvs_cursor_seek(
    struct hse_kvs_cursor *handle,
    const void *           key,
    uint32_t               len,
    const void *           limit,
    uint32_t               limit_len,
    struct kvs_ktuple *    kt)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (ev(cursor->kci_err))
        return cursor->kci_err;

    /* Set up limits if provided */
    if (ev(limit_len > HSE_KVS_KEY_LEN_MAX))
        return merr(EINVAL);

    if (limit && limit_len) {
        memcpy(cursor->kci_limit, limit, limit_len);
        handle->kc_filter.kcf_maxkey = cursor->kci_limit;
        handle->kc_filter.kcf_maxklen = cursor->kci_limit_len = limit_len;
    } else {
        handle->kc_filter.kcf_maxkey = NULL;
        handle->kc_filter.kcf_maxklen = 0;
    }

    /* Cannot use limits with  reverse cursor */
    if (ev(handle->kc_filter.kcf_maxkey && cursor->kci_reverse))
        return merr(EINVAL);

    if (!key) {
        key = cursor->kci_prefix;
        len = cursor->kci_reverse ? HSE_KVS_KEY_LEN_MAX : cursor->kci_pfxlen;
    }

    cursor->kci_err = ikvs_cursor_seek(cursor, key, len);
    if (ev(cursor->kci_err))
        return cursor->kci_err;

    /* Peek at the next key and optionally copy into kt */
    ikvs_cursor_replenish(cursor);
    if (kt && !cursor->kci_eof)
        kt->kt_data =
            key_obj_copy(cursor->kci_buf, HSE_KVS_KEY_LEN_MAX, (uint *)&kt->kt_len, cursor->kci_last);
    cursor->kci_need_toss = 0;
    cursor->kci_need_seek = 0;

    if (cursor->kci_eof || ev(cursor->kci_err)) {
        /* If this seek caused the cursor to land on eof, store this key so the cursor
         * remains positionally stable.
         */
        if (cursor->kci_eof) {
            cursor->kci_last_klen = len;
            memcpy(cursor->kci_last_kbuf, key, len);
            key2kobj(&cursor->kci_last_kobj, cursor->kci_last_kbuf, cursor->kci_last_klen);
            cursor->kci_last = &cursor->kci_last_kobj;
        }

        if (kt)
            kt->kt_len = 0;
        return cursor->kci_err;
    }

    return 0;
}

void
kvs_cursor_perfc_alloc(uint prio, const char *group, struct perfc_set *ccp, struct perfc_set *cdp)
{
    perfc_alloc(kvs_cc_perfc_op, group, "set", prio, ccp);
    perfc_alloc(kvs_cd_perfc_op, group, "set", prio, cdp);
}

void
kvs_cursor_perfc_free(struct perfc_set *pcs_cc, struct perfc_set *pcs_cd)
{
    perfc_free(pcs_cc);
    perfc_free(pcs_cd);
}

void
kvs_cursor_perfc_init(void)
{
    struct perfc_ivl *ivl;
    int               i;
    uint64_t          boundv[PERFC_IVL_MAX];
    merr_t            err;

    /* Allocate interval instance for the distribution counters (pow2). */
    for (i = 0; i < PERFC_IVL_MAX; i++)
        boundv[i] = 1 << i;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &ivl);
    if (err) {
        log_warnx("cursor perfc, unable to allocate pow2 ivl", err);
        return;
    }

    kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl = ivl;
    kvs_cd_perfc_op[PERFC_DI_CD_ACTIVEKVSETS_CN].pcn_ivl = ivl;
    kvs_cd_perfc_op[PERFC_DI_CD_TOMBSPERPROBE].pcn_ivl = ivl;
}

void
kvs_cursor_perfc_fini(void)
{
    struct perfc_ivl *ivl;

    ivl = kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl;
    if (ev(!ivl))
        return;

    kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl = 0;
    kvs_cd_perfc_op[PERFC_DI_CD_TOMBSPERPROBE].pcn_ivl = 0;
    kvs_cd_perfc_op[PERFC_DI_CD_ACTIVEKVSETS_CN].pcn_ivl = 0;

    perfc_ivl_destroy(ivl);
}

merr_t
kvs_curcache_init(void)
{
    struct kvs_cursor_impl *kci HSE_MAYBE_UNUSED;
    uint                        nperbkt, i;
    ulong                       mavail;
    size_t                      sz;

    assert(!ikvs_curcachev);

    sz = sizeof(*kci);
    sz += (HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX); /* For kci_buf */
    sz += (HSE_KVS_KEY_LEN_MAX * 3);                /* For prefix, last_key and limit */
    kvs_cursor_impl_alloc_sz = sz;

    ikvs_curcachec = clamp_t(uint, (get_nprocs() / 2), 16, 48);

    /* Limit the cursor cache to roughly 10% of system memory,
     * but no less than 1GB and no more than 32GB.
     *
     * [HSE_REVISIT] mapi breaks initialization of mavail by hse_meminfo().
     */
    mavail = 0;
    hse_meminfo(NULL, &mavail, 0);

    sz = (mavail * HSE_CURCACHE_SZ_PCT) / 100;
    sz = clamp_t(size_t, sz, HSE_CURCACHE_SZ_MIN, HSE_CURCACHE_SZ_MAX);

    /* Reduce number of buckets in the cache until there are a reasonable
     * number of entries per bucket.
     */
    while (1) {
        nperbkt = sz / (HSE_CURSOR_SZ_MIN * ikvs_curcachec);
        if (nperbkt >= 16 || ikvs_curcachec < 8)
            break;

        ikvs_curcachec /= 2;
    }

    /* We offset the bucket address from the beginning of the page by some
     * number of cache lines (the "color") to mitigate cache line aliasing,
     * so we need to account for the overall increased size.
     */
    ikvs_colormax = (PAGE_SIZE / 4) / sizeof(struct curcache_bucket);
    ikvs_curcachesz = PAGE_ALIGN(sizeof(struct curcache_bucket) * ikvs_colormax);
    ikvs_curcachesz += PAGE_ALIGN(sizeof(struct curcache_entry) * nperbkt);

    ikvs_curcachev = vlb_alloc(ikvs_curcachesz * ikvs_curcachec);
    if (ev(!ikvs_curcachev))
        return merr(ENOMEM);

    for (i = 0; i < ikvs_curcachec; ++i) {
        struct curcache_bucket *bkt = ikvs_curcachev + ikvs_curcache_idx2bktoff(i);

        memset(bkt, 0, sizeof(*bkt));
        mutex_init(&bkt->cb_lock);
        bkt->cb_entrymax = nperbkt;
        bkt->cb_root = RB_ROOT;
    }

    log_debug("bktsz %zu, bktc %u, nperbkt %u", ikvs_curcachesz, ikvs_curcachec, nperbkt);

    setup_timer(&ikvs_curcache_timer, ikvs_curcache_timer_cb, 0);
    add_timer(&ikvs_curcache_timer);

    return 0;
}

void
kvs_curcache_fini(void)
{
    uint entryc = 0, entrymax = 0, bktc = 0;
    int  i;

    assert(ikvs_curcachev);

    while (!del_timer(&ikvs_curcache_timer))
        usleep(333);

    for (i = 0; i < ikvs_curcachec; ++i) {
        struct curcache_bucket *bkt = ikvs_curcachev + ikvs_curcache_idx2bktoff(i);

        /* All calls to kvs_close() should have emptied the cache.
         */
        assert(!bkt->cb_root.rb_node);
        assert(!bkt->cb_evicted);
        assert(!bkt->cb_active);

        bktc += (bkt->cb_entryc > 0);
        entryc += bkt->cb_entryc;
        entrymax += bkt->cb_entrymax;

        mutex_destroy(&bkt->cb_lock);
    }

    if (bktc > 0) {
        log_info(
            "bucket utilization %.1lf%% (%u/%u), entry utilization %.1lf%% (%u/%u)",
            (bktc * 100.0) / ikvs_curcachec,
            bktc,
            ikvs_curcachec,
            (entryc * 100.0) / entrymax,
            entryc,
            entrymax);
    }

    vlb_free(ikvs_curcachev, ikvs_curcachesz * ikvs_curcachec);
    ikvs_curcachev = NULL;
}
