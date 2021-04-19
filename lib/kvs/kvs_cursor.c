/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/kvdb_perfc.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/vlb.h>
#include <hse_util/string.h>
#include <hse_util/fmt.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cn_cursor.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/cursor.h>

#include <sys/sysinfo.h>

/* clang-format off */

struct perfc_name kvs_cc_perfc_op[] = {
    NE(PERFC_RA_CC_HIT,             2, "Cursor cache hit/restore rate", "r_cc_hit(/s)"),
    NE(PERFC_RA_CC_MISS,            2, "Cursor cache miss/create rate", "r_cc_miss(/s)"),
    NE(PERFC_RA_CC_SAVEFAIL,        2, "Cursor cache save/fail rate",   "r_cc_savefail(/s)"),
    NE(PERFC_RA_CC_RESTFAIL,        2, "Cursor cache restore/fail",     "r_cc_restfail(/s)"),
    NE(PERFC_RA_CC_UPDATE,          2, "Cursor cache update rate",      "r_cc_update(/s)"),
    NE(PERFC_RA_CC_SAVE,            3, "Cursor cache save rate",        "r_cc_save(/s)"),

    /* The following counters require setting kvs_debug to 16 or 32.
     */
    NE(PERFC_BA_CC_EAGAIN_C0,       3, "c0 EAGAIN count",               "c_cc_c0_eagain"),
    NE(PERFC_BA_CC_EAGAIN_CN,       3, "cn EAGAIN count",               "c_cc_cn_eagain"),
    NE(PERFC_BA_CC_INIT_CREATE_C0,  3, "c0 cursor init/create count",   "c_cc_c0_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_C0,  3, "c0 cursor init/update count",   "c_cc_c0_initupd"),
    NE(PERFC_BA_CC_INIT_CREATE_CN,  3, "cn cursor init/create count",   "c_cc_cn_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_CN,  3, "cn cursor init/update count",   "c_cc_cn_initupd"),
    NE(PERFC_BA_CC_UPDATED_C0,      3, "c0 cursor update count",        "c_cc_c0_update"),
    NE(PERFC_BA_CC_UPDATED_CN,      3, "cn cursor update count",        "c_cc_cn_update"),
};

NE_CHECK(kvs_cc_perfc_op, PERFC_EN_CC, "cursor cache perfc ops table/enum mismatch");

struct perfc_name kvs_cd_perfc_op[] = {
    NE(PERFC_LT_CD_SAVE,            2, "cursor cache save latency",     "l_cc_save(ns)",    7),
    NE(PERFC_LT_CD_RESTORE,         2, "cursor cache restore latency",  "l_cc_restore(ns)", 7),

    /* The following counters require setting kvs_debug to 16 or 32.
     */
    NE(PERFC_LT_CD_CREATE_CN,       2, "cn cursor create latency",      "l_cc_create_cn", 7),
    NE(PERFC_LT_CD_UPDATE_CN,       2, "cn cursor update latency",      "l_cc_update_cn", 7),
    NE(PERFC_LT_CD_CREATE_C0,       2, "c0 cursor create latency",      "l_cc_create_c0", 7),
    NE(PERFC_LT_CD_UPDATE_C0,       2, "c0 cursor update latency",      "l_cc_update_c0", 7),
    NE(PERFC_DI_CD_READPERSEEK,     2, "Cursor reads per seek",         "d_cc_readperseek", 7),
    NE(PERFC_DI_CD_TOMBSPERPROBE,   2, "Tombs seen per pfx probe",      "d_cc_tombsperprobe", 7),
    NE(PERFC_DI_CD_ACTIVEKVSETS_CN, 2, "kvsets in cursors view",        "d_cc_activekvsets"),
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

struct curcache_entry {
    u64                     cc_ttl;
    uint64_t                cc_key;
    struct kvs_cursor_impl *cc_next;
};

/**
 * struct cache_bucket - a list of cursors per rb_node
 * @node:     how we link into rb tree
 * @oldkey:   curcache comparator key of oldest cursor on %list
 * @oldttl:   expiration time (ns) of oldest cursor on %list
 * @list:     list of cached cursors
 * @next:     free list linkage (see cca_free)
 * @cnt:      number of cursors on %list
 *
 * [HSE_REVISIT] Rename "struct curcache_bucket" to "struct curcache_node"
 * and then "struct curcache" to "struct curcache_bucket".
 */
struct curcache_bucket {
    struct rb_node          node;
    uint64_t                oldkey;
    uint64_t                oldttl;
    union {
        struct kvs_cursor_impl *list;
        struct curcache_bucket *next;
    };
    int                     cnt;
};

/**
 * struct curcache - cursor cache bucket
 * @cca_lock:     lock to protect update of all fields in the bucket
 * @cca_entryc:   number of entries allocated from entryv[]
 * @cca_root:     root of the rb tree
 * @cca_evicted:  head of list of evicted entries
 * @cca_free:     head of list of free entries
 * @cca_active:   current number of active entries
 * @cca_entrymax: max entries in cca_entryv[]
 * @cca_entryv:   vector of curcache list nodes
 */
struct curcache {
    struct mutex            cca_lock HSE_ALIGNED(SMP_CACHE_BYTES * 2);
    uint                    cca_entryc;

    struct rb_root          cca_root HSE_ALIGNED(SMP_CACHE_BYTES);
    struct kvs_cursor_impl *cca_evicted;
    struct curcache_bucket *cca_free;
    uint                    cca_active;
    uint                    cca_entrymax;
    struct curcache_bucket  cca_entryv[] HSE_ALIGNED(SMP_CACHE_BYTES);
};

struct kvs_cursor_impl {
    struct hse_kvs_cursor   kci_handle;
    struct curcache_entry   kci_cache;
    struct perfc_set *      kci_cc_pc;
    struct perfc_set *      kci_cd_pc;
    struct ikvs *           kci_kvs;
    struct c0_cursor *      kci_c0cur;
    void *                  kci_cncur;
    struct cursor_summary   kci_summary;

    /* current values for each cursor read */
    struct kvs_kvtuple kci_c0kv;
    struct kvs_kvtuple kci_cnkv;
    u32                kci_limit_len;
    void *             kci_limit;

    /* The kci_last* fields matter only when the kci_need_seek
     * flag is set.
     */
    struct kvs_kvtuple *kci_last; /* last tuple read */
    u8 *                kci_last_kbuf;
    u32                 kci_last_klen;

    u32 kci_c0_eof : 1;
    u32 kci_cn_eof : 1;
    u32 kci_need_read_c0 : 1;
    u32 kci_need_read_cn : 1;
    u32 kci_need_toss : 1;
    u32 kci_need_seek : 1;
    u32 kci_reverse : 1;

    u32    kci_pfxlen;
    u64    kci_pfxhash;
    merr_t kci_err; /* bad cursor, must destroy */

    char kci_prefix[];
} HSE_ALIGNED(SMP_CACHE_BYTES);

static struct kmem_cache   *ikvs_cursor_zone  HSE_READ_MOSTLY;
static size_t               ikvs_curcachesz   HSE_READ_MOSTLY;
static void                *ikvs_curcachev    HSE_READ_MOSTLY;
static uint                 ikvs_curcachec    HSE_READ_MOSTLY;
static uint                 ikvs_colormax     HSE_READ_MOSTLY;

struct timer_list           ikvs_curcache_timer;
atomic_t                    ikvs_curcache_pruning;

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

#define cursor_h2r(h)       container_of(h, struct kvs_cursor_impl, kci_handle)
#define node2bucket(n)      container_of(n, struct curcache_bucket, node)

/* clang-format on */

/**
 * ikvs_cursor_bkt_alloc() - allocate a cursor cache node
 * @cca:  ptr to cursor cache
 *
 * Caller must hold the cursor cache lock.
 */
static struct curcache_bucket *
ikvs_cursor_bkt_alloc(struct curcache *cca)
{
    struct curcache_bucket *bkt;

    bkt = cca->cca_free;
    if (bkt) {
        cca->cca_free = bkt->next;
        return bkt;
    }

    if (cca->cca_entryc < cca->cca_entrymax) {
        bkt = cca->cca_entryv + cca->cca_entryc++;
        memset(bkt, 0, sizeof(*bkt));
    }

    return bkt;
}

/**
 * ikvs_cursor_bkt_free() - free a cursor cache node
 * @cca:  ptr to cursor cache
 * @bkt:  ptr to bucket to free
 *
 * Caller must hold the cursor cache lock.
 */
static void
ikvs_cursor_bkt_free(struct curcache *cca, struct curcache_bucket *bkt)
{
    bkt->next = cca->cca_free;
    cca->cca_free = bkt;
}

static HSE_ALWAYS_INLINE
struct curcache *
ikvs_curcache_idx2bkt(uint idx)
{
    size_t offset;

    idx %= ikvs_curcachec;

    offset = ikvs_curcachesz * idx;
    offset += sizeof(struct curcache) * (idx % ikvs_colormax);

    return ikvs_curcachev + offset;
}

/**
 * ikvs_curcache_prune() - prune all expired cursors matching the given %kvs
 * @cca:       cursor cache bucket ptr
 * @kvs:       %kvs to match (or NULL to match all)
 * @now:       evict cursors where %now exceeds their time-to-live
 * @retiredp:  ptr to count of cursors evicted
 */
static void
ikvs_curcache_prune_impl(
    struct curcache *cca,
    struct ikvs *    kvs,
    u64              now,
    uint            *retiredp,
    uint            *evictedp)
{
    struct kvs_cursor_impl *evicted, *old;
    struct rb_node *node;
    uint ndestroyed = 0;
    uint nretired = 0;

    mutex_lock(&cca->cca_lock);
    node = rb_first(&cca->cca_root);
    evicted = cca->cca_evicted;
    cca->cca_evicted = NULL;

    while (node) {
        struct curcache_bucket *bkt = rb_entry(node, typeof(*bkt), node);

        node = rb_next(node);

        if (now < bkt->oldttl)
            continue;

        if (kvs && kvs != bkt->list->kci_kvs)
            continue;

        while (( old = bkt->list )) {
            if (old->kci_cache.cc_ttl > now)
                break;

            bkt->list = old->kci_cache.cc_next;
            old->kci_cache.cc_next = evicted;
            evicted = old;
            ++nretired;
            --bkt->cnt;
        }

        if (old) {
            bkt->oldkey = old->kci_cache.cc_key;
            bkt->oldttl = old->kci_cache.cc_ttl;
        } else {
            rb_erase(&bkt->node, &cca->cca_root);
            ikvs_cursor_bkt_free(cca, bkt);
        }
    }

    /* Cursors on the evicted list have already been accounted for...
     */
    cca->cca_active -= nretired;
    mutex_unlock(&cca->cca_lock);

    while (( old = evicted )) {
        evicted = old->kci_cache.cc_next;
        ikvs_cursor_destroy(&old->kci_handle);
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
        struct curcache *cca = ikvs_curcache_idx2bkt(i);

        ikvs_curcache_prune_impl(cca, kvs, kvs ? U64_MAX : jclock_ns, &nretired, &nevicted);
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

static HSE_ALWAYS_INLINE struct curcache *
ikvs_td2cca(struct ikvs *kvs, const bool save)
{
    static thread_local struct curcache *tls_cca_bkt;

    if (HSE_UNLIKELY( !tls_cca_bkt )) {
        static atomic_t g_cca_idx;

        tls_cca_bkt = ikvs_curcache_idx2bkt(atomic_inc_return(&g_cca_idx));
    }

    return tls_cca_bkt;
}

/* ikvs_curcache_key() constructs a key for the cursor cache comparator
 * such that we can compare the kvs and distinguishing cursor attributes
 * in just one comparison.  This reduces the number of cursor objects
 * we have to touch while walking the tree.
 */
static HSE_ALWAYS_INLINE uint64_t
ikvs_curcache_key(const uint64_t gen, const char *prefix, const u64 pfxhash, const bool reverse)
{
    return (gen << 24) | (pfxhash & 0xfffffau) | ((!!prefix) << 1) | reverse;
}

static HSE_ALWAYS_INLINE int
ikvs_curcache_cmp(struct curcache_bucket *bkt, uint64_t key, const void *prefix, size_t pfxlen)
{
    if (key != bkt->oldkey)
        return (key < bkt->oldkey) ? -1 : 1;

    if (!prefix)
        return 0;

    return keycmp(prefix, pfxlen, bkt->list->kci_prefix, bkt->list->kci_pfxlen);
}

static struct kvs_cursor_impl *
ikvs_curcache_insert(struct curcache *cca, struct kvs_cursor_impl *cur)
{
    struct rb_node **       link, *parent;
    struct curcache_bucket *bkt;
    int                     rc;

    mutex_lock(&cca->cca_lock);
    link = &cca->cca_root.rb_node;
    parent = NULL;

    while (*link) {
        parent = *link;
        bkt = node2bucket(parent);

        rc = ikvs_curcache_cmp(bkt, cur->kci_cache.cc_key, cur->kci_prefix, cur->kci_pfxlen);
        if (rc < 0)
            link = &parent->rb_left;
        else if (rc > 0)
            link = &parent->rb_right;
        else
            break;
    }

    if (*link) {
        struct kvs_cursor_impl **pp = &bkt->list;

        /* The list of cursors is sorted oldest-to-youngest from head-to-tail
         * to reduce unnecessary retirements (because ikvs_curcache_remove()
         * always removes the oldest cursor from a given list).
         */
        while (1) {
            struct kvs_cursor_impl *old = *pp;

            if (!old || cur->kci_cache.cc_ttl > old->kci_cache.cc_ttl) {
                cur->kci_cache.cc_next = old;
                cca->cca_active++;
                *pp = cur;
                break;
            }

            pp = &old->kci_cache.cc_next;
        }

        if (++bkt->cnt > 8 || cca->cca_active > cca->cca_entrymax) {
            cur = bkt->list;
            bkt->list = cur->kci_cache.cc_next;
            cur->kci_cache.cc_next = cca->cca_evicted;
            cca->cca_evicted = cur;
            cca->cca_active--;
            pp = &bkt->list;
            --bkt->cnt;
        }

        if (&bkt->list == pp) {
            bkt->oldkey = bkt->list->kci_cache.cc_key;
            bkt->oldttl = bkt->list->kci_cache.cc_ttl;
        }

        cur = NULL;
    }
    else {
        bkt = ikvs_cursor_bkt_alloc(cca);
        if (bkt) {
            bkt->oldkey = cur->kci_cache.cc_key;
            bkt->oldttl = cur->kci_cache.cc_ttl;
            bkt->list = cur;
            bkt->cnt = 1;

            rb_link_node(&bkt->node, parent, link);
            rb_insert_color(&bkt->node, &cca->cca_root);

            cur->kci_cache.cc_next = NULL;
            cca->cca_active++;
            cur = NULL;
        }
    }
    mutex_unlock(&cca->cca_lock);

    return cur;
}

static struct kvs_cursor_impl *
ikvs_curcache_remove(struct curcache *cca, uint64_t key, const void *prefix, size_t pfx_len)
{
    struct rb_node *        node;
    struct kvs_cursor_impl *old;
    struct curcache_bucket *bkt;
    int                     rc;

    mutex_lock(&cca->cca_lock);
    node = cca->cca_root.rb_node;
    old = NULL;
    bkt = NULL;

    while (node) {
        bkt = node2bucket(node);

        rc = ikvs_curcache_cmp(bkt, key, prefix, pfx_len);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            break;
    }

    if (node) {
        old = bkt->list;
        bkt->list = old->kci_cache.cc_next;
        cca->cca_active--;

        if (--bkt->cnt == 0) {
            rb_erase(node, &cca->cca_root);
            ikvs_cursor_bkt_free(cca, bkt);
        } else {
            bkt->oldkey = bkt->list->kci_cache.cc_key;
            bkt->oldttl = bkt->list->kci_cache.cc_ttl;
        }
    }
    mutex_unlock(&cca->cca_lock);

    return old;
}

/* Prune from the cursor cache all cursors related to the given kvs.
 * This function is called by kvs_close() to purge the cache of all
 * cursors bound to the given kvs.
 */
void
ikvs_cursor_reap(struct ikvs *kvs)
{
    ikvs_curcache_prune(kvs);

    /* Wait for the async pruner in case we ran concurrently...
     */
    while (atomic_read(&ikvs_curcache_pruning) > 0)
        usleep(333);
}

/**
 * ikvs_maint_task() - periodic maintenance on ikvs
 *
 * Currently, this function is called with the ikdb_lock held, ugh...
 */
void
ikvs_maint_task(struct ikvs *kvs, u64 now)
{
    cn_periodic(kvs->ikv_cn, now);
}

static void
ikvs_cursor_reset(struct kvs_cursor_impl *cursor)
{
    struct ikvs *kvs = cursor->kci_kvs;

    cursor->kci_c0_eof = 0;
    cursor->kci_cn_eof = 0;
    cursor->kci_need_read_c0 = 1;
    cursor->kci_need_read_cn = 1;
    cursor->kci_need_seek = 0;
    cursor->kci_need_toss = 1;

    cursor->kci_cc_pc = NULL;
    cursor->kci_cd_pc = NULL;

    cursor->kci_cache.cc_ttl = jclock_ns + kvs->ikv_rp.kvs_cursor_ttl * USEC_PER_SEC;

    if (kvs->ikv_rp.kvs_debug & 16)
        cursor->kci_cc_pc = &kvs->ikv_cc_pc;
    if (kvs->ikv_rp.kvs_debug & 32)
        cursor->kci_cd_pc = &kvs->ikv_cd_pc;
}

static struct kvs_cursor_impl *
ikvs_cursor_restore(struct ikvs *kvs, const void *prefix, size_t pfx_len, u64 pfxhash, bool reverse)
{
    struct kvs_cursor_impl *cur;
    struct curcache *       cca;
    u64                     tstart;
    uint64_t key;

    tstart = perfc_lat_startl(&kvs->ikv_cd_pc, PERFC_LT_CD_RESTORE);

    key = ikvs_curcache_key(kvs->ikv_gen, prefix, pfxhash, reverse);

    cca = ikvs_td2cca(kvs, false);
    cur = ikvs_curcache_remove(cca, key, prefix, pfx_len);
    if (!cur) {
        PERFC_INC_RU(&kvs->ikv_cc_pc, PERFC_RA_CC_MISS);
        return NULL;
    }

    if (cur->kci_c0cur) {
        struct c0_cursor *c0cur = cur->kci_c0cur;
        merr_t            err;

        err = c0_cursor_restore(c0cur);
        if (ev(err)) {
            perfc_inc(&kvs->ikv_cc_pc, PERFC_RA_CC_RESTFAIL);
            ikvs_cursor_destroy(&cur->kci_handle);
            return NULL;
        }
    }

    perfc_lat_record(&kvs->ikv_cd_pc, PERFC_LT_CD_RESTORE, tstart);
    PERFC_INC_RU(&kvs->ikv_cc_pc, PERFC_RA_CC_HIT);

    return cur;
}

static void
cursor_summary_log(struct kvs_cursor_impl *cur)
{
    struct cursor_summary *s = &cur->kci_summary;
    char                   buf[512], gbuf[128], ctime[32], utime[32], pfx[32];
    int                    i, j, o;

    o = 0;
    i = s->n_dgen & 3;

    if (cur->kci_pfxlen)
        fmt_hex(pfx, sizeof(pfx), cur->kci_prefix, cur->kci_pfxlen);
    else
        strlcpy(pfx, "(null)", sizeof(pfx));

    if (s->dgen[i]) {
        /* dgen buffer has wrapped */
        for (j = 0; j < 4; ++j) {
            o += sprintf(gbuf + o, "%lu,", (ulong)s->dgen[i]);
            i = (i + 1) & 3;
        }
    } else {
        for (j = 0; j < i; ++j)
            o += sprintf(gbuf + o, "%lu,", (ulong)s->dgen[j]);
        if (i == 0)
            o += sprintf(gbuf + o, "%u,", 0);
    }
    gbuf[--o] = 0;

    fmt_time(ctime, sizeof(ctime), s->created);
    fmt_time(utime, sizeof(utime), s->updated);

    snprintf(
        buf,
        sizeof(buf),
        "skidx %d pfx %s len %d created %s updated %s dgen %s "
        "view 0x%lu readc0 %u readcn %u kvms %u kvset %u "
        "ingest %u trim %u bind %u upd %u eof %d",
        s->skidx,
        pfx,
        cur->kci_pfxlen,
        ctime,
        utime,
        gbuf,
        (ulong)s->seqno,
        s->read_c0,
        s->read_cn,
        s->n_kvms,
        s->n_kvset,
        s->n_dgen,
        s->n_trim,
        s->n_bind,
        s->n_update,
        cur->kci_c0_eof || cur->kci_cn_eof);

    hse_log(HSE_NOTICE "cursor: %p %s", cur, buf);
}

static void
_perfc_readperseek_record(struct kvs_cursor_impl *cur)
{
    if (!cur->kci_summary.util)
        return;

    perfc_rec_sample(cur->kci_cd_pc, PERFC_DI_CD_READPERSEEK, cur->kci_summary.util);
    cur->kci_summary.util = 0;
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
    u64 tstart;

    if ((kvs->ikv_rp.kvs_debug & 64)) {
        cursor_summary_log(cur);
        _perfc_readperseek_record(cur);
    }

    tstart = perfc_lat_startl(&kvs->ikv_cd_pc, PERFC_LT_CD_SAVE);

    if (cur->kci_cache.cc_ttl > jclock_ns) {
        struct curcache *cca;

        cca = ikvs_td2cca(kvs, true);
        cur = ikvs_curcache_insert(cca, cur);
    }

    if (cur) {
        perfc_inc(&kvs->ikv_cc_pc, PERFC_RA_CC_SAVEFAIL);
        ikvs_cursor_destroy(&cur->kci_handle);
    } else {
        perfc_lat_record(&kvs->ikv_cd_pc, PERFC_LT_CD_SAVE, tstart);
        PERFC_INC_RU(&kvs->ikv_cc_pc, PERFC_RA_CC_SAVE);
    }
}

struct hse_kvs_cursor *
ikvs_cursor_alloc(struct ikvs *kvs, const void *prefix, size_t pfx_len, bool reverse)
{
    struct kvs_cursor_impl *cur;
    size_t                  len;
    u64                     pfxhash;

    pfxhash = (prefix && pfx_len > 0) ? key_hash64(prefix, pfx_len) : 0;

    cur = ikvs_cursor_restore(kvs, prefix, pfx_len, pfxhash, reverse);
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

    len = reverse ? HSE_KVS_KLEN_MAX : pfx_len;

    cur = kmem_cache_alloc(ikvs_cursor_zone);
    if (ev(!cur))
        return NULL;

    memset(cur, 0, sizeof(*cur));
    cur->kci_cache.cc_key = ikvs_curcache_key(kvs->ikv_gen, prefix, pfxhash, reverse);
    if (kvs->ikv_rp.kvs_debug & 16)
        cur->kci_cc_pc = &kvs->ikv_cc_pc;
    if (kvs->ikv_rp.kvs_debug & 32)
        cur->kci_cd_pc = &kvs->ikv_cd_pc;
    cur->kci_kvs = kvs;
    cur->kci_pfxlen = pfx_len;
    cur->kci_pfxhash = pfxhash;
    if (prefix)
        memcpy(cur->kci_prefix, prefix, pfx_len);

    cur->kci_last_kbuf = (void *)cur->kci_prefix + len;
    cur->kci_limit = (void *)cur->kci_last_kbuf + HSE_KVS_KLEN_MAX;
    cur->kci_limit_len = 0;
    cur->kci_handle.kc_filter.kcf_maxkey = 0;

    cur->kci_reverse = reverse;
    ikvs_cursor_reset(cur);

    /* Pad with 0xff to make reverse cursor seek-to-pfx simple */
    if (reverse)
        memset(cur->kci_prefix + pfx_len, 0xFF, HSE_KVS_KLEN_MAX - pfx_len);

    return &cur->kci_handle;
}

void
ikvs_cursor_free(struct hse_kvs_cursor *cursor)
{
    if (cursor->kc_err)
        ikvs_cursor_destroy(cursor);
    else
        ikvs_cursor_save(cursor_h2r(cursor));
}

static HSE_ALWAYS_INLINE u64
now(void)
{
    struct timespec ts;

    get_realtime(&ts);

    return ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

merr_t
ikvs_cursor_init(struct hse_kvs_cursor *cursor)
{
    struct kvs_cursor_impl *cur = cursor_h2r(cursor);
    struct ikvs *           kvs = cur->kci_kvs;
    void *                  c0 = kvs->ikv_c0;
    void *                  cn = kvs->ikv_cn;
    u64                     seqno = cursor->kc_seq;
    merr_t                  err = 0;
    u32                     flags;
    bool                    updated;
    u64                     tstart;

    /* no context: update must seek to beginning */
    cur->kci_last = 0;

    /* summaries are only useful if debugging is enabled */
    if (kvs->ikv_rp.kvs_debug & 64) {
        memset(&cur->kci_summary, 0, sizeof(cur->kci_summary));
        cur->kci_summary.addr = cur;
        cur->kci_summary.seqno = seqno;
        cur->kci_summary.created = now();
    }

    assert((!!cur->kci_c0cur ^ !!cur->kci_cncur) == 0);

    /* Create/Update c0 cursor */
    if (!cur->kci_c0cur) {
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_CREATE_C0);

        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_CREATE_C0);
        err = c0_cursor_create(
            c0,
            seqno,
            cur->kci_reverse,
            cur->kci_prefix,
            cur->kci_pfxlen,
            &cur->kci_summary,
            &cur->kci_c0cur);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_CREATE_C0, tstart);
    } else {
        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_C0);
        err = c0_cursor_update(cur->kci_c0cur, seqno, &flags);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

        if (flags & CURSOR_FLAG_SEQNO_CHANGE)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_UPDATE_C0);

        cur->kci_need_seek = 1;
    }

    if (ev(err)) {
        if (merr_errno(err) == EAGAIN)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_EAGAIN_C0);
        goto error;
    }

    /* Create/Update cn cursor */
    if (!cur->kci_cncur) {
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_CREATE_CN);

        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_CREATE_CN);
        err = cn_cursor_create(
            cn,
            seqno,
            cur->kci_reverse,
            cur->kci_prefix,
            cur->kci_pfxlen,
            &cur->kci_summary,
            &cur->kci_cncur);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_CREATE_CN, tstart);
    } else {
        tstart = perfc_lat_startu(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_CN);
        err = cn_cursor_update(cur->kci_cncur, seqno, &updated);
        perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_UPDATE_CN, tstart);

        if (updated)
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_INIT_UPDATE_CN);
        cur->kci_need_seek = 1;
    }

    if (ev(merr_errno(err) == EAGAIN))
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_EAGAIN_CN);

    if (!err) {
        u32 active, total;

        cn_cursor_active_kvsets(cur->kci_cncur, &active, &total);
        perfc_rec_sample(cur->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);

        cur->kci_need_toss = 0;
        if (cur->kci_need_seek) {
            memcpy(cur->kci_last_kbuf, cur->kci_prefix, cur->kci_pfxlen);
            cur->kci_last_klen = cur->kci_pfxlen;
            if (cur->kci_reverse) {
                cur->kci_last_klen = HSE_KVS_KLEN_MAX;
                memset(cur->kci_last_kbuf + cur->kci_pfxlen, 0xFF, HSE_KVS_KLEN_MAX - cur->kci_pfxlen);
            }
        }
    }

error:
    cursor->kc_err = err;
    return err;
}

merr_t
ikvs_cursor_bind_txn(struct hse_kvs_cursor *handle, struct kvdb_ctxn *ctxn)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (ev(!cursor->kci_c0cur))
        return merr(ENXIO);

    c0_cursor_bind_txn(cursor->kci_c0cur, ctxn);

    return 0;
}

void
ikvs_cursor_destroy(struct hse_kvs_cursor *handle)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (handle->kc_bind)
        kvdb_ctxn_cursor_unbind(handle->kc_bind);
    if (cursor->kci_c0cur)
        c0_cursor_destroy(cursor->kci_c0cur);

    if (cursor->kci_cncur)
        cn_cursor_destroy(cursor->kci_cncur);

    kmem_cache_free(ikvs_cursor_zone, cursor);
}

merr_t
ikvs_cursor_update(struct hse_kvs_cursor *handle, u64 seqno)
{
    struct kvs_cursor_impl *cursor = (void *)handle;
    struct kvdb_ctxn_bind * bind = handle->kc_bind;
    u32                     flags;
    bool                    updated;
    u64                     tstart;

    perfc_inc(&cursor->kci_kvs->ikv_cc_pc, PERFC_RA_CC_UPDATE);

    ++cursor->kci_summary.n_update;
    cursor->kci_summary.seqno = seqno;
    cursor->kci_summary.updated = now();
    assert(seqno == handle->kc_seq);

    _perfc_readperseek_record(cursor);

    if (bind)
        handle->kc_gen = atomic64_read(&bind->b_gen);

    /* Copy out last key that was read */
    if (cursor->kci_last) {
        cursor->kci_last_klen = cursor->kci_last->kvt_key.kt_len;
        memcpy(cursor->kci_last_kbuf,
               cursor->kci_last->kvt_key.kt_data,
               cursor->kci_last->kvt_key.kt_len);
    } else {
        cursor->kci_need_toss = 0;
        cursor->kci_last_klen = cursor->kci_reverse ? HSE_KVS_KLEN_MAX : cursor->kci_pfxlen;
        memcpy(cursor->kci_last_kbuf,
               cursor->kci_prefix,
               cursor->kci_last_klen);
    }

    /* Update c0 cursor */
    tstart = perfc_lat_startu(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_C0);

    cursor->kci_err = c0_cursor_update(cursor->kci_c0cur, seqno, &flags);
    if (ev(cursor->kci_err)) {
        if (merr_errno(cursor->kci_err) == EAGAIN)
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EAGAIN_C0);
        return cursor->kci_err;
    }
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

    if (flags & CURSOR_FLAG_SEQNO_CHANGE)
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_C0);

    /* HSE_REVISIT: Skip cn update if this is a bound cursor
     */
    /* Update cn cursor */
    tstart = perfc_lat_startu(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_CN);

    cursor->kci_err = cn_cursor_update(cursor->kci_cncur, seqno, &updated);
    if (ev(cursor->kci_err)) {
        if (merr_errno(cursor->kci_err) == EAGAIN)
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EAGAIN_CN);

        return cursor->kci_err;
    }
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_CN, tstart);

    if (updated) {
        u32 active, total;

        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_CN);

        cn_cursor_active_kvsets(cursor->kci_cncur, &active, &total);
        perfc_rec_sample(cursor->kci_cd_pc, PERFC_DI_CD_ACTIVEKVSETS_CN, active);
    }

    cursor->kci_need_seek = 1;

    return 0;
}

static inline int
pfx_cmp(struct kvs_cursor_impl *cursor)
{
    return keycmp_prefix(
        cursor->kci_c0kv.kvt_key.kt_data,
        cursor->kci_c0kv.kvt_key.kt_len,
        cursor->kci_cnkv.kvt_key.kt_data,
        cursor->kci_cnkv.kvt_key.kt_len);
}

static inline int
cursor_cmp(struct kvs_cursor_impl *cursor)
{
    return keycmp(
        cursor->kci_c0kv.kvt_key.kt_data,
        cursor->kci_c0kv.kvt_key.kt_len,
        cursor->kci_cnkv.kvt_key.kt_data,
        cursor->kci_cnkv.kvt_key.kt_len);
}

static inline merr_t
read_c0(struct kvs_cursor_impl *cursor)
{
    bool eof;
    merr_t err;

    err = c0_cursor_read(cursor->kci_c0cur, &cursor->kci_c0kv, &eof);
    if (ev(err))
        return err;

    cursor->kci_c0_eof = eof ? 1 : 0;
    return 0;
}

static inline merr_t
read_cn(struct kvs_cursor_impl *cursor)
{
    bool eof;
    merr_t err;

    err = cn_cursor_read(cursor->kci_cncur, &cursor->kci_cnkv, &eof);
    if (ev(err))
        return err;

    cursor->kci_cn_eof = eof ? 1 : 0;
    return 0;
}

static merr_t
cursor_pop(struct kvs_cursor_impl *cursor, bool *eof)
{
    merr_t err = 0;
    int rc;
    bool c0ptomb = false;

    *eof = false;
    if (!cursor->kci_c0_eof && cursor->kci_need_read_c0) {
        err = read_c0(cursor);
        if (ev(err))
            goto out;

        cursor->kci_need_read_c0 = 0;
    }

    if (!cursor->kci_cn_eof && cursor->kci_need_read_cn) {
        err = read_cn(cursor);
        if (ev(err))
            goto out;

        cursor->kci_need_read_cn = 0;
    }

    if (cursor->kci_c0_eof && cursor->kci_cn_eof) {
        *eof = true;
        return 0;
    }

    if (cursor->kci_c0_eof) {
        rc = 1;
    } else if (cursor->kci_cn_eof) {
        rc = -1;
    } else {
        c0ptomb = HSE_CORE_IS_PTOMB(cursor->kci_c0kv.kvt_value.vt_data);
        rc = c0ptomb ? pfx_cmp(cursor) : cursor_cmp(cursor);
        rc = cursor->kci_reverse ? -rc : rc;
    }

    /* c0 and cn drop their own dups. The only case that needs to be handled when c0
     * and cn read the same key
     */
    if (rc <= 0) {
        cursor->kci_last = &cursor->kci_c0kv;
        cursor->kci_need_read_c0 = 1;
        if (rc == 0)
            cursor->kci_need_read_cn = 1;
    } else {
        cursor->kci_last = &cursor->kci_cnkv;
        cursor->kci_need_read_cn = 1;
    }

out:
    return err;
}

void
drop_prefixes(struct kvs_cursor_impl *cursor, struct kvs_ktuple *pt)
{
    struct kvs_ktuple *cnkt = &cursor->kci_cnkv.kvt_key;

    assert(cursor->kci_last == &cursor->kci_c0kv);

    while (!cursor->kci_cn_eof &&
           !keycmp_prefix(pt->kt_data, pt->kt_len, cnkt->kt_data, cnkt->kt_len)) {
        bool eof;

        cursor->kci_need_read_c0 = 0;
        cursor->kci_need_read_cn = 1;
        cursor_pop(cursor, &eof);
    }

    /* Restore state: caller was in the middle of processing the ptomb from c0.
     */
    cursor->kci_need_read_c0 = 1;
    cursor->kci_need_read_cn = 0;
}

merr_t
cursor_replenish(struct kvs_cursor_impl *cursor, bool *eofp)
{
    bool is_ptomb, is_tomb;
    merr_t err = 0;

    *eofp = false;
    do {
        err = cursor->kci_err = cursor_pop(cursor, eofp);
        if (ev(err))
            goto out;

        if (*eofp)
            goto out;

        is_tomb = HSE_CORE_IS_TOMB(cursor->kci_last->kvt_value.vt_data);

        is_ptomb = HSE_CORE_IS_PTOMB(cursor->kci_last->kvt_value.vt_data);
        if (is_ptomb) {
            struct kvs_ktuple *pt_key;

            pt_key = &cursor->kci_last->kvt_key;
            drop_prefixes(cursor, pt_key);
        }

    } while (is_ptomb || is_tomb);

out:
    return err;
}

static merr_t
cursor_seek(struct kvs_cursor_impl *cursor, struct kvs_ktuple *c0kt, struct kvs_ktuple *cnkt)
{
    struct hse_kvs_cursor *handle = &cursor->kci_handle;
    merr_t err = 0;

    err = c0_cursor_seek(cursor->kci_c0cur, c0kt->kt_data, c0kt->kt_len,
                         handle->kc_filter.kcf_maxkey ? &handle->kc_filter : 0, 0);
    if (ev(err))
        goto out;

    err = cn_cursor_seek(cursor->kci_cncur, cnkt->kt_data, cnkt->kt_len,
                         handle->kc_filter.kcf_maxkey ? &handle->kc_filter : 0, 0);
    if (ev(err))
        goto out;

out:
    return err;
}

merr_t
kvs_cursor_read(struct hse_kvs_cursor *handle, struct kvs_kvtuple *kvt, bool *eofp)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    if (ev(cursor->kci_err)) {
        if (ev(merr_errno(cursor->kci_err) != EAGAIN))
            return cursor->kci_err;

        cursor->kci_err = 0;
    }

    if (cursor->kci_need_seek) {
        struct kvs_ktuple key = { 0 };
        bool toss = cursor->kci_need_toss;

        cursor->kci_err = kvs_cursor_seek(&cursor->kci_handle,
                                           cursor->kci_last_kbuf,
                                           cursor->kci_last_klen, 0, 0, &key);

        if (ev(cursor->kci_err))
            return cursor->kci_err;

        *eofp = cursor->kci_c0_eof && cursor->kci_cn_eof;
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
        toss = toss &&
               !keycmp(cursor->kci_last_kbuf, cursor->kci_last_klen, key.kt_data, key.kt_len);

        if (toss) {
            cursor->kci_err = cursor_replenish(cursor, eofp);
            if (ev(cursor->kci_err))
                return cursor->kci_err;
        }
    }

    cursor->kci_err = cursor_replenish(cursor, eofp);
    if (ev(cursor->kci_err))
        return cursor->kci_err;

    cursor->kci_need_toss = 1;
    if (*eofp)
        return 0;

    *kvt = *cursor->kci_last;
    return 0;
}

merr_t
kvs_cursor_seek(
    struct hse_kvs_cursor *handle,
    const void *           key,
    u32                    len,
    const void *           limit,
    u32                    limit_len,
    struct kvs_ktuple *    kt)
{
    struct kvs_cursor_impl * cursor = (void *)handle;
    struct kvs_ktuple c0kt, cnkt;
    bool eof;

    if (ev(cursor->kci_err)) {
        if (ev(merr_errno(cursor->kci_err) != EAGAIN))
            return cursor->kci_err;

        cursor->kci_err = 0;
    }

    /* Set up limits if provided */
    if (ev(limit_len > HSE_KVS_KLEN_MAX))
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
        len = cursor->kci_reverse ? HSE_KVS_KLEN_MAX : cursor->kci_pfxlen;
    }

    kvs_ktuple_init(&c0kt, key, len);

    cursor->kci_c0_eof = 0;
    cursor->kci_cn_eof = 0;

    cnkt = c0kt;

    cursor->kci_err = cursor_seek(cursor, &c0kt, &cnkt);
    if (ev(cursor->kci_err))
        return cursor->kci_err;

    cursor->kci_need_read_c0 = 1;
    cursor->kci_need_read_cn = 1;
    cursor->kci_err = cursor_replenish(cursor, &eof);

    cursor->kci_need_toss = 0;
    cursor->kci_need_seek = 0;

    if (eof || ev(cursor->kci_err)) {
        if (kt)
            kt->kt_len = 0;
        return cursor->kci_err;
    }

    if (kt)
        *kt = cursor->kci_last->kvt_key;

    cursor->kci_need_read_c0 = 0;
    cursor->kci_need_read_cn = 0;

    return 0;
}

void
kvs_cursor_perfc_alloc(
        const char *dbname,
        struct perfc_set *pcs_cc,
        struct perfc_set *pcs_cd)
{
    if (perfc_ctrseti_alloc(
            COMPNAME, dbname, kvs_cc_perfc_op, PERFC_EN_CC, "set", pcs_cc))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");

    if (perfc_ctrseti_alloc(
            COMPNAME, dbname, kvs_cd_perfc_op, PERFC_EN_CD, "set", pcs_cd))
        hse_log(HSE_ERR "cannot alloc kvs perf counters");
}

void
kvs_cursor_perfc_free(
        struct perfc_set *pcs_cc,
        struct perfc_set *pcs_cd)
{
    perfc_ctrseti_free(pcs_cc);
    perfc_ctrseti_free(pcs_cd);
}

void
kvs_cursor_perfc_init(void)
{
    struct perfc_ivl *ivl;
    int               i;
    u64               boundv[PERFC_IVL_MAX];
    merr_t            err;

    /* Allocate interval instance for the distribution counters (pow2). */
    for (i = 0; i < PERFC_IVL_MAX; i++)
        boundv[i] = 1 << i;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &ivl);
    if (err) {
        hse_elog(HSE_WARNING "cursor perfc, unable to allocate pow2 ivl: @@e", err);
        return;
    }

    kvs_cd_perfc_op[PERFC_DI_CD_READPERSEEK].pcn_ivl = ivl;
    kvs_cd_perfc_op[PERFC_DI_CD_ACTIVEKVSETS_CN].pcn_ivl = ivl;
    kvs_cd_perfc_op[PERFC_DI_CD_TOMBSPERPROBE].pcn_ivl = ivl;
}

void
kvs_cursor_perfc_fini(void)
{
    const struct perfc_ivl *ivl;

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
    struct kmem_cache *zone;
    uint nperbkt, i;
    ulong mavail;
    size_t sz;

    assert(!ikvs_cursor_zone);
    assert(!ikvs_curcachev);

    sz = sizeof(struct kvs_cursor_impl);
    sz += HSE_KVS_KLEN_MAX * 3; /* prefix, last key, limit */

    zone = kmem_cache_create("cursor", sz, alignof(struct kvs_cursor_impl), 0, NULL);
    if (ev(!zone))
        return merr(ENOMEM);

    ikvs_cursor_zone = zone;

    ikvs_curcachec = clamp_t(uint, (get_nprocs() / 2), 16, 48);

    /* Limit the cursor cache to roughly 10% of system memory,
     * but no less than 1GB and no more than 32GB.
     */
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
    ikvs_colormax = (PAGE_SIZE / 4) / sizeof(struct curcache);
    ikvs_curcachesz = PAGE_ALIGN(sizeof(struct curcache) * ikvs_colormax);
    ikvs_curcachesz += PAGE_ALIGN(sizeof(struct curcache_bucket) * nperbkt);

    ikvs_curcachev = vlb_alloc(ikvs_curcachesz * ikvs_curcachec);
    if (ev(!ikvs_curcachev)) {
        kmem_cache_destroy(ikvs_cursor_zone);
        return merr(ENOMEM);
    }

    for (i = 0; i < ikvs_curcachec; ++i) {
        struct curcache *cca = ikvs_curcache_idx2bkt(i);

        memset(cca, 0, sizeof(*cca));
        mutex_init(&cca->cca_lock);
        cca->cca_entrymax = nperbkt;
        cca->cca_root = RB_ROOT;
    }

    hse_log(HSE_NOTICE "%s: bktsz %zu, bktc %u, nperbkt %u",
            __func__, ikvs_curcachesz, ikvs_curcachec, nperbkt);

    setup_timer(&ikvs_curcache_timer, ikvs_curcache_timer_cb, 0);
    add_timer(&ikvs_curcache_timer);

    return 0;
}

void
kvs_curcache_fini(void)
{
    uint entryc = 0, entrymax = 0, bktc = 0;
    int i;

    assert(ikvs_cursor_zone);
    assert(ikvs_curcachev);

    while (!del_timer(&ikvs_curcache_timer))
        usleep(333);

    for (i = 0; i < ikvs_curcachec; ++i) {
        struct curcache *cca = ikvs_curcache_idx2bkt(i);

        /* All calls to kvs_close() should have emptied the cache.
         */
        assert(!cca->cca_root.rb_node);
        assert(!cca->cca_evicted);
        assert(!cca->cca_active);

        bktc += (cca->cca_entryc > 0);
        entryc += cca->cca_entryc;
        entrymax += cca->cca_entrymax;

        mutex_destroy(&cca->cca_lock);
    }

    if (bktc > 0) {
        hse_log(HSE_NOTICE
                "%s: bucket utilization %.1lf%% (%u/%u), entry utilization %.1lf%% (%u/%u)",
                __func__, (bktc * 100.0) / ikvs_curcachec, bktc, ikvs_curcachec,
                (entryc * 100.0) / entrymax, entryc, entrymax);
    }

    vlb_free(ikvs_curcachev, ikvs_curcachesz * ikvs_curcachec);
    ikvs_curcachev = NULL;

    kmem_cache_destroy(ikvs_cursor_zone);
    ikvs_cursor_zone = NULL;
}
