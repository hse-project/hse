/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */
// TODO Gaurav: revisit list of includes
#include <hse/hse.h>
#include <hse/kvdb_perfc.h>

#include <hse_util/platform.h>
#include <hse_util/slab.h>
#include <hse_util/string.h>
#include <hse_util/event_counter.h>
#include <hse_util/perfc.h>
#include <hse_util/darray.h>
#include <hse_util/timing.h>
#include <hse_util/fmt.h>
#include <hse_util/byteorder.h>
#include <hse_util/slab.h>
#include <hse_util/table.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>
#include <hse_ikvdb/cn_cursor.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cursor.h>

#include "kvs_params.h"

#include <syscall.h>

struct perfc_name kvs_cc_perfc_op[] = {
    NE(PERFC_BA_CC_RESTORE, 2, "Count of cursor restores", "c_restores"),
    NE(PERFC_BA_CC_ALLOC, 2, "Count of cursor allocations", "c_allocations"),

    NE(PERFC_BA_CC_RETIRE_KVS, 3, "Count of cursor retires due to age", "c_ret_kvs"),
    NE(PERFC_BA_CC_SAVE, 3, "Count of cursor saves", "c_saves"),
    NE(PERFC_BA_CC_SAVE_DESTROY, 3, "Count of cursor restore failures", "c_rest_fails"),
    NE(PERFC_BA_CC_EAGAIN_C0, 3, "Count of c0 EAGAIN's", "c_c0_eagain"),
    NE(PERFC_BA_CC_EAGAIN_CN, 3, "Count of cN EAGAIN's", "c_cN_eagain"),
    NE(PERFC_BA_CC_INIT_CREATE_C0, 3, "Count of c0 cursor init/creates", "c_c0_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_C0, 3, "Count of c0 cursor init/updates", "c_c0_initup"),
    NE(PERFC_BA_CC_INIT_CREATE_CN, 3, "Count of cN cursor init/creates", "c_cN_initcr"),
    NE(PERFC_BA_CC_INIT_UPDATE_CN, 3, "Count of cN cursor init/updates", "c_cN_initup"),
    NE(PERFC_BA_CC_UPDATED_C0, 3, "Count of c0 cursor updates", "c_c0up"),
    NE(PERFC_BA_CC_UPDATED_CN, 3, "Count of cN cursor updates", "c_cNup"),
    NE(PERFC_BA_CC_DESTROY, 3, "Count of cursor destroys", "c_destroys"),
    NE(PERFC_BA_CC_UPDATE, 3, "Count of cursor updates", "c_updates"),
    NE(PERFC_BA_CC_SEEK, 3, "Count of cursor seeks", "c_seeks"),
    NE(PERFC_BA_CC_SEEK_READ, 3, "Count of cursor replenishes", "c_replenish"),
    NE(PERFC_BA_CC_EOF, 3, "Count of cursor eof", "c_eofs"),
    NE(PERFC_BA_CC_READ_C0, 2, "Count of cursor c0 reads", "c_c0_reads"),
    NE(PERFC_BA_CC_READ_CN, 2, "Count of cursor cN reads", "c_cN_reads"),
};

NE_CHECK(kvs_cc_perfc_op, PERFC_EN_CC, "cursor cache perfc ops table/enum mismatch");

struct perfc_name kvs_cd_perfc_op[] = {
    NE(PERFC_LT_CD_CREATE_CN, 2, "cn cursor create latency", "c_lat_create_cn", 7),
    NE(PERFC_LT_CD_UPDATE_CN, 2, "cn cursor update latency", "c_lat_update_cn", 7),
    NE(PERFC_LT_CD_READ_CN, 2, "cn cursor read latency", "c_lat_read_cn", 7),
    NE(PERFC_LT_CD_SEEK_CN, 2, "cn cursor seek latency", "c_lat_seek_cn", 7),
    NE(PERFC_LT_CD_CREATE_C0, 2, "c0 cursor create latency", "c_lat_create_c0", 7),
    NE(PERFC_LT_CD_UPDATE_C0, 2, "c0 cursor update latency", "c_lat_update_c0", 7),
    NE(PERFC_LT_CD_READ_C0, 2, "c0 cursor read latency", "c_lat_read_c0", 7),
    NE(PERFC_LT_CD_SEEK_C0, 2, "c0 cursor seek latency", "c_lat_seek_c0", 7),
    NE(PERFC_DI_CD_READPERSEEK, 2, "Cursor reads per seek", "c_dist_readperseek", 7),
    NE(PERFC_DI_CD_TOMBSPERPROBE, 2, "Tombs seens per pfx probe", "c_dist_tombsperprobe", 7),

    NE(PERFC_LT_CD_SAVE, 2, "cursor save latency", "c_lat_save", 7),
    NE(PERFC_LT_CD_RESTORE, 2, "cursor restore latency", "c_lat_restore", 7),

    NE(PERFC_DI_CD_ACTIVEKVSETS_CN, 2, "Active kvsets in the cursor's view", "c_dist_activekvsets"),
};

NE_CHECK(kvs_cd_perfc_op, PERFC_EN_CD, "cursor dist perfc ops table/enum mismatch");

/*
 * A cursor resides in one of two places, exclusively:
 * the ikvdb_kvs.kk_cursors list if it is active,
 * the ikvs.cursor_cache tree if it is inactive (and cached).
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
    u64                     cc_cn_ttl;
    u64                     cc_c0_ttl;
    struct kvs_cursor_impl *cc_next;
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
    u32 kci_pfxlen : 8;
    u32 kci_unused : 16;

    u64    kci_pfxhash;
    merr_t kci_err; /* bad cursor, must destroy */

    char kci_prefix[];
} __aligned(SMP_CACHE_BYTES);

static struct kmem_cache *kvs_cursor_zone;

void
kvs_perfc_init(void)
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

#define bit_on(x, y) ((cursor->x & y) == y)
enum { BIT_NONE = 0, BIT_C0 = 1, BIT_CN = 2, BIT_BOTH = 3 };

#define cursor_h2r(h) container_of(h, struct kvs_cursor_impl, kci_handle)

#define node2bucket(n) container_of(n, struct cache_bucket, node)

/**
 * ikvs_cursor_bkt_alloc() - allocate a cursor cache node
 * @cca:  ptr to cursor cache
 *
 * Caller must hold the cursor cache lock.
 */
static struct cache_bucket *
ikvs_cursor_bkt_alloc(struct curcache *cca)
{
    struct cache_bucket *bkt;

    bkt = cca->cca_bkt_head;
    if (bkt) {
        cca->cca_bkt_head = *(void **)bkt;
    } else {
        bkt = calloc(1, sizeof(*bkt));
        if (bkt)
            bkt->freeme = true;
        ev(1);
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
void
ikvs_cursor_bkt_free(struct curcache *cca, struct cache_bucket *bkt)
{
    if (bkt->freeme) {
        free(bkt);
        ev(1);
    } else {
        *(void **)bkt = cca->cca_bkt_head;
        cca->cca_bkt_head = bkt;
    }
}

static void
ikvs_curcache_preen(
    struct curcache *cca,
    struct ikvs *    kvs,
    u64              now,
    uint *           cursors_retiredp)
{
    struct rb_node *        node;
    struct kvs_cursor_impl *todo;
    uint                    cursors_retired;

    cursors_retired = 0;
    todo = NULL;

    mutex_lock(&cca->cca_lock);
    node = rb_first(&cca->cca_root);

    for (; node; node = rb_next(node)) {
        struct cache_bucket *    b = node2bucket(node);
        struct kvs_cursor_impl **pp;
        u64                      oldest;

        if (now < b->oldest)
            continue;

        /* for each cursor in list */
        oldest = U64_MAX;
        pp = &b->list;

        while (*pp) {
            struct kvs_cursor_impl *cur = *pp;

            if (now >= cur->kci_cache.cc_ttl) {
                --b->cnt;
                *pp = cur->kci_cache.cc_next;
                cur->kci_cache.cc_next = todo;
                todo = cur;
                ++cursors_retired;
                continue;
            }

            if (cur->kci_cache.cc_ttl < oldest)
                oldest = cur->kci_cache.cc_ttl;

            pp = &(*pp)->kci_cache.cc_next;
        }

        if (b->cnt == 0) {
            rb_erase(node, &cca->cca_root);

            /* iterator now invalid -- catch it next time */
            ikvs_cursor_bkt_free(cca, b);
            break;
        }

        if (oldest > b->oldest)
            b->oldest = oldest;
    }
    mutex_unlock(&cca->cca_lock);

    /* [MU_REVIST] Offload cleanup to a workqueue...
     */
    while (todo) {
        struct kvs_cursor_impl *cur = todo;

        todo = cur->kci_cache.cc_next;
        ikvs_cursor_destroy(&cur->kci_handle);
    }

    *cursors_retiredp += cursors_retired;
}

/*
 * ikvs_maint_task - periodic maintenance on ikvs structures (cursors)
 *
 * This routine must be called periodically to give back resources
 * that have been held too long.  Both c0 and cn have resources claimed
 * by cursors in applications, which may not be cooperative with the
 * underlying needs.  This task works against the cursor cache.
 *
 * HSE_REVISIT:
 * There will be a peer task in ikvdb that works against the active cursors.
 * It will need to call into the working part of this loop.
 *
 * Currently, this function is called with the ikdb_lock held, ugh...
 */
void
ikvs_maint_task(struct ikvs *kvs, u64 now)
{
    uint cursors_retired = 0;
    int  idx, i;

    /* Preen only a few cursor cache buckets per call...
     */
    for (i = 0; i < (NELEM(kvs->ikv_curcachev) / 4) + 1; ++i) {
        idx = kvs->ikv_curcache_preenidx++ % NELEM(kvs->ikv_curcachev);
        ikvs_curcache_preen(kvs->ikv_curcachev + idx, kvs, now, &cursors_retired);
    }

    if (cursors_retired > 0)
        perfc_add(&kvs->ikv_cc_pc, PERFC_BA_CC_RETIRE_KVS, cursors_retired);

    cn_periodic(kvs->ikv_cn, now);
}

/*
 * for each node in tree: remove from tree, destroy cursor
 *
 * the rb_erase invalidates iteration, thus we loop on
 * the first entry, hoping this minimizes rebalancing
 *
 * NB: since reap is called during close, it is not a problem
 * to keep the tree locked at this point
 */
void
ikvs_cursor_reap(struct ikvs *kvs)
{
    struct curcache *cca;
    struct rb_node * node;
    int              i;

    for (i = 0; i < NELEM(kvs->ikv_curcachev); ++i) {
        cca = kvs->ikv_curcachev + i;

        mutex_lock(&cca->cca_lock);
        node = rb_first(&cca->cca_root);

        while (node) {
            struct cache_bucket *b = node2bucket(node);

            while (b->list) {
                struct kvs_cursor_impl *cur = b->list;

                b->list = cur->kci_cache.cc_next;
                ikvs_cursor_destroy(&cur->kci_handle);
            }

            rb_erase(node, &cca->cca_root);
            ikvs_cursor_bkt_free(cca, b);

            node = rb_first(&cca->cca_root);
        }
        mutex_unlock(&cca->cca_lock);
    }
}

static struct curcache *
ikvs_td2cca(struct ikvs *kvs, u64 pfxhash)
{
    uint cpuid, nodeid, i;

    if (unlikely( syscall(SYS_getcpu, &cpuid, &nodeid) ))
        nodeid = raw_smp_processor_id();

    i = pthread_self() % (NELEM(kvs->ikv_curcachev) / 2);
    i += (nodeid % 2) * (NELEM(kvs->ikv_curcachev) / 2);

    return kvs->ikv_curcachev + i;
}

static int
ikvs_curcache_cmp(
    const struct kvs_cursor_impl *cur,
    const void *                  prefix,
    size_t                        pfx_len,
    bool                          reverse)
{
    if (reverse && !cur->kci_reverse)
        return -1;
    else if (!reverse && cur->kci_reverse)
        return 1;

    if (prefix && !cur->kci_prefix)
        return -1;
    else if (!prefix && cur->kci_prefix)
        return 1;

    if (!prefix && !cur->kci_prefix)
        return 0;

    return keycmp(prefix, pfx_len, cur->kci_prefix, cur->kci_pfxlen);
}

static struct kvs_cursor_impl *
ikvs_curcache_insert(struct curcache *cca, struct kvs_cursor_impl *cur)
{
    struct rb_node **       link, *parent;
    struct rb_root *        root;
    struct kvs_cursor_impl *old;
    struct cache_bucket *   b;
    int                     rc;

    mutex_lock(&cca->cca_lock);
    root = &cca->cca_root;
    link = &root->rb_node;
    parent = 0;

    while (*link) {
        parent = *link;
        old = node2bucket(parent)->list;

        rc = ikvs_curcache_cmp(old, cur->kci_prefix, cur->kci_pfxlen, cur->kci_reverse);
        if (rc < 0)
            link = &(*link)->rb_left;
        else if (rc > 0)
            link = &(*link)->rb_right;
        else
            break;
    }

    /*
     * if *link, this is the cursor to replace
     * else cursor does not exist, and this is insert point
     */

    if (*link) {
        b = node2bucket(parent);
        cur->kci_cache.cc_next = b->list;
        b->list = cur;
        ++b->cnt;
        cur = NULL;
    } else {
        b = ikvs_cursor_bkt_alloc(cca);
        if (b) {
            b->list = cur;
            b->cnt = 1;
            b->oldest = cur->kci_cache.cc_ttl;
            cur->kci_cache.cc_next = 0;

            rb_link_node(&b->node, parent, link);
            rb_insert_color(&b->node, root);
            cur = NULL;
        }
    }
    mutex_unlock(&cca->cca_lock);

    return cur;
}

static struct kvs_cursor_impl *
ikvs_curcache_remove(struct curcache *cca, const void *prefix, size_t pfx_len, bool reverse)
{
    struct rb_node *        node;
    struct kvs_cursor_impl *cur;
    struct cache_bucket *   b;
    int                     rc;

    mutex_lock(&cca->cca_lock);
    node = cca->cca_root.rb_node;
    cur = NULL;
    b = 0;

    while (node) {
        b = node2bucket(node);
        cur = b->list;

        rc = ikvs_curcache_cmp(cur, prefix, pfx_len, reverse);
        if (rc < 0)
            node = node->rb_left;
        else if (rc > 0)
            node = node->rb_right;
        else
            break;
    }

    if (node) {
        assert(b);
        b->list = cur->kci_cache.cc_next;
        cur->kci_cache.cc_next = 0;
        --b->cnt;
        if (b->list == 0) {
            rb_erase(node, &cca->cca_root);
            ikvs_cursor_bkt_free(cca, b);
        }
    } else {
        cur = NULL;
    }
    mutex_unlock(&cca->cca_lock);

    return cur;
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

    if (kvs->ikv_rp.kvs_debug & 16)
        cursor->kci_cc_pc = &kvs->ikv_cc_pc;
    if (kvs->ikv_rp.kvs_debug & 32)
        cursor->kci_cd_pc = &kvs->ikv_cd_pc;
}

__attribute__((__noinline__))
static struct kvs_cursor_impl *
ikvs_cursor_restore(struct ikvs *kvs, const void *prefix, size_t pfx_len, u64 pfxhash, bool reverse)
{
    struct kvs_cursor_impl *cur;
    struct curcache *       cca;
    u64                     tstart;

    tstart = perfc_lat_startu(&kvs->ikv_cd_pc, PERFC_LT_CD_RESTORE);

    cca = ikvs_td2cca(kvs, pfxhash);
    cur = ikvs_curcache_remove(cca, prefix, pfx_len, reverse);
    if (!cur)
        return NULL;

    if (cur->kci_c0cur) {
        struct c0_cursor *c0cur = cur->kci_c0cur;
        merr_t            err;

        err = c0_cursor_restore(c0cur);
        if (ev(err)) {
            perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_SAVE_DESTROY);
            ikvs_cursor_destroy(&cur->kci_handle);
            return 0;
        }
    }

    perfc_lat_record(cur->kci_cd_pc, PERFC_LT_CD_RESTORE, tstart);

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

static void
ikvs_cursor_save(struct kvs_cursor_impl *cur)
{
    struct perfc_set *cc_pc, *cd_pc;
    struct curcache * cca;
    struct ikvs *     kvs = cur->kci_kvs;
    u64               tstart;
    u64               now;
    u64               cur_age;

    if (unlikely(kvs->ikv_rp.kvs_debug & 64)) {
        cursor_summary_log(cur);
        _perfc_readperseek_record(cur);
    }

    cd_pc = cur->kci_cd_pc;
    cc_pc = cur->kci_cc_pc;

    /* this is how cursor caching is disabled */
    cur_age = kvs->ikv_rp.kvs_cursor_ttl;

    if (cur_age == 0)
        goto discard;

    /*
     * theory: this cursor has a more recent set of resources than
     * a cached cursor, so release the older resources and replace
     * with the more current
     */
    tstart = perfc_lat_start(cd_pc);
    now = tstart ?: get_time_ns();
    cur->kci_cache.cc_ttl = now + cur_age * 1048576;

    cca = ikvs_td2cca(kvs, cur->kci_pfxhash);
    cur = ikvs_curcache_insert(cca, cur);

    /*
     * NB: it is unsafe to use cur after the unlock, because
     * ikvs_maint_task may destroy it if we lose our context;
     * remember kvs before we insert cur, and use kvs after
     * since the kvs will remain addressable during this call.
     */
    perfc_lat_record(cd_pc, PERFC_LT_CD_SAVE, tstart);
    perfc_inc(cc_pc, PERFC_BA_CC_SAVE);

discard:
    if (cur) {
        perfc_inc(cc_pc, PERFC_BA_CC_SAVE_DESTROY);
        ikvs_cursor_destroy(&cur->kci_handle);
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
        perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_RESTORE);

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

    cur = kmem_cache_alloc(kvs_cursor_zone);
    if (ev(!cur))
        return NULL;

    memset(cur, 0, sizeof(*cur));
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

    perfc_inc(cur->kci_cc_pc, PERFC_BA_CC_ALLOC);

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

static __always_inline u64
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

        tstart = perfc_lat_start(cur->kci_cd_pc);
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
        tstart = perfc_lat_start(cur->kci_cd_pc);
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

        tstart = perfc_lat_start(cur->kci_cd_pc);
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
        tstart = perfc_lat_start(cur->kci_cd_pc);
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
    merr_t                  err;

    if (ev(!cursor->kci_c0cur))
        return merr(ENXIO);

    ++cursor->kci_summary.n_bind;
    err = c0_cursor_bind_txn(cursor->kci_c0cur, ctxn);

    if (ev(merr_errno(err) == EAGAIN))
        perfc_inc(&cursor->kci_kvs->ikv_cc_pc, PERFC_BA_CC_EAGAIN_C0);

    return err;
}

void
ikvs_cursor_destroy(struct hse_kvs_cursor *handle)
{
    struct kvs_cursor_impl *cursor = (void *)handle;

    perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_DESTROY);

    if (handle->kc_bind)
        kvdb_ctxn_cursor_unbind(handle->kc_bind);
    if (cursor->kci_c0cur)
        c0_cursor_destroy(cursor->kci_c0cur);

    if (cursor->kci_cncur)
        cn_cursor_destroy(cursor->kci_cncur);

    kmem_cache_free(kvs_cursor_zone, cursor);
}

merr_t
ikvs_cursor_update(struct hse_kvs_cursor *handle, u64 seqno)
{
    struct kvs_cursor_impl *cursor = (void *)handle;
    struct kvdb_ctxn_bind * bind = handle->kc_bind;
    u32                     flags;
    bool                    updated;
    u64                     tstart;

    perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATE);

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
    tstart = perfc_lat_start(cursor->kci_cd_pc);
    cursor->kci_err = c0_cursor_update(cursor->kci_c0cur, seqno, &flags);
    if (ev(cursor->kci_err)) {
        if (merr_errno(cursor->kci_err) == EAGAIN)
            perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_EAGAIN_C0);
        return cursor->kci_err;
    }
    perfc_lat_record(cursor->kci_cd_pc, PERFC_LT_CD_UPDATE_C0, tstart);

    if (flags & CURSOR_FLAG_SEQNO_CHANGE)
        perfc_inc(cursor->kci_cc_pc, PERFC_BA_CC_UPDATED_C0);

    /* Update cn cursor */
    tstart = perfc_lat_start(cursor->kci_cd_pc);
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

    // TODO Gaurav: should this expect EAGAIN?
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

    // TODO Gaurav: should this expect EAGAIN?
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
    bool is_ptomb;
    merr_t err = 0;

    *eofp = false;
    do {
        const void *dbg_curr_key __maybe_unused;
        size_t dbg_curr_klen __maybe_unused;

        err = cursor->kci_err = cursor_pop(cursor, eofp);
        if (ev(err))
            goto out;

        if (*eofp)
            goto out;

        dbg_curr_key  = cursor->kci_last->kvt_key.kt_data;
        dbg_curr_klen = cursor->kci_last->kvt_key.kt_len;

        is_ptomb = HSE_CORE_IS_PTOMB(cursor->kci_last->kvt_value.vt_data);
        if (is_ptomb) {
            struct kvs_ktuple *pt_key;

            pt_key = &cursor->kci_last->kvt_key;
            drop_prefixes(cursor, pt_key);
        }

    } while (is_ptomb);

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
        struct kvs_ktuple key;
        bool toss = cursor->kci_need_toss;

        // TODO Gaurav: make sure that kci_last_kbuf/klen contains:
        //   1. pfx/pfx0xFFF... after a create, or
        //   2. kci_last's contents after an update
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

        // TODO Gaurav: if you set need_read_c0/cn = 0 after the seek's replenish, the following one will be a peek
        if (toss) {
            cursor->kci_err = cursor_replenish(cursor, eofp);
            if (ev(cursor->kci_err))
                return cursor->kci_err;
        }
    }

    cursor->kci_err = cursor_replenish(cursor, eofp);
    if (ev(cursor->kci_err))
        return cursor->kci_err;

    if (*eofp)
        return 0;

    cursor->kci_need_toss = 1;
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

#undef bit_on

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

merr_t
kvs_cursor_zone_alloc(void)
{
    struct kmem_cache *zone;
    size_t             sz;

    sz = sizeof(struct kvs_cursor_impl);
    sz += HSE_KVS_KLEN_MAX * 3; /* prefix, last key, limit */

    zone = kmem_cache_create("cursor", sz, SMP_CACHE_BYTES, 0, NULL);
    if (ev(!zone))
        return merr(ENOMEM);

    kvs_cursor_zone = zone;
    return 0;
}

void
kvs_cursor_zone_free(void)
{
    kmem_cache_destroy(kvs_cursor_zone);
    kvs_cursor_zone = NULL;
}
