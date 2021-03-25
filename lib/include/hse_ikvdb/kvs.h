/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_IKVS_H
#define HSE_KVS_IKVS_H

#include <hse_util/arch.h>
#include <hse_util/list.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/mutex.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/query_ctx.h>

#define TOMBSPAN_MIN_WIDTH 8

/* MTF_MOCK_DECL(kvs) */

/*- Internal Key Value Store  -----------------------------------------------*/

struct hse_kvdb_opspec;
struct kvdb_ctxn;
struct kvdb_kvs;
struct cndb;
struct ikvs;
struct ikvdb;
struct ikvdb_impl;
struct mpool;
struct kvs_cparams;
struct kvs_rparams;
struct cn;
struct cn_kvdb;

struct kc_filter {
    const void *kcf_maxkey;
    size_t      kcf_maxklen;
};

struct hse_kvs_cursor {
    struct perfc_set *     kc_pkvsl_pc;
    struct kvdb_kvs *      kc_kvs;
    struct kvdb_ctxn_bind *kc_bind;
    u64                    kc_gen;
    u64                    kc_seq;
    u64                    kc_create_time;
    volatile bool          kc_on_list;
    unsigned int           kc_flags;
    merr_t                 kc_err;
    atomic_t *             kc_cursor_cnt;
    struct kc_filter       kc_filter;
    void                  *kc_viewcookie;
};

merr_t
kvs_open(
    struct ikvdb *      kvdb,
    struct kvdb_kvs *   kvs,
    const char *        mp_name,
    struct mpool *      ds,
    struct cndb *       cndb,
    struct kvs_rparams *rp,
    struct kvdb_health *health,
    struct cn_kvdb *    cn_kvdb,
    uint                kvs_oflags);

struct mpool *
kvs_ds_get(struct ikvs *ikvs);

merr_t
kvs_close(struct ikvs *ikvs);

struct perfc_set *
ikvs_perfc_pkvsl(struct ikvs *ikvs);

merr_t
ikvs_put(
    struct ikvs *            ikvs,
    struct hse_kvdb_opspec * os,
    struct kvs_ktuple *      kt,
    const struct kvs_vtuple *vt,
    u64                      seqno);

merr_t
ikvs_get(
    struct ikvs *           ikvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     key,
    u64                     seqno,
    enum key_lookup_res *   res,
    struct kvs_buf *        vbuf);

merr_t
ikvs_del(struct ikvs *ikvs, struct hse_kvdb_opspec *os, struct kvs_ktuple *key, u64 seqno);

merr_t
ikvs_pfx_probe(
    struct ikvs *           kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    u64                     seqno,
    enum key_lookup_res *   res,
    struct kvs_buf *        kbuf,
    struct kvs_buf *        vbuf);

merr_t
ikvs_prefix_del(struct ikvs *ikvs, struct hse_kvdb_opspec *os, struct kvs_ktuple *key, u64 seqno);

u16
ikvs_index(struct ikvs *ikvs);

void
ikvs_maint_task(struct ikvs *ikvs, u64 now);

struct hse_kvs_cursor *
ikvs_cursor_alloc(struct ikvs *ikvs, const void *prefix, size_t pfx_len, bool reverse);

void
ikvs_cursor_free(struct hse_kvs_cursor *cursor);

merr_t
ikvs_cursor_init(struct hse_kvs_cursor *cursor);

merr_t
ikvs_cursor_bind_txn(struct hse_kvs_cursor *handle, struct kvdb_ctxn *ctxn);

void
ikvs_cursor_destroy(struct hse_kvs_cursor *cursor);

merr_t
kvs_cursor_seek(
    struct hse_kvs_cursor *cursor,
    const void *           key,
    u32                    len,
    const void *           limit,
    u32                    limit_len,
    struct kvs_ktuple *    kt);

merr_t
ikvs_cursor_update(struct hse_kvs_cursor *cursor, u64 seqno);

merr_t
kvs_cursor_read(struct hse_kvs_cursor *cursor, struct kvs_kvtuple *kvt, bool *eof);

void
kvs_perfc_register(void *pc);

struct cn *
kvs_cn(struct ikvs *ikvs);

/* MTF_MOCK */
struct ikvdb_impl *
kvdb_kvs_parent(struct kvdb_kvs *kk);

/* MTF_MOCK */
struct kvs_cparams *
kvdb_kvs_cparams(struct kvdb_kvs *kk);

/* MTF_MOCK */
u32
kvdb_kvs_flags(struct kvdb_kvs *kk);

/* MTF_MOCK */
u64
kvdb_kvs_cnid(struct kvdb_kvs *kk);

/* MTF_MOCK */
char *
kvdb_kvs_name(struct kvdb_kvs *kk);

/* MTF_MOCK */
void
kvdb_kvs_set_ikvs(struct kvdb_kvs *kk, struct ikvs *ikvs);

void
kvs_perfc_init(void);

void
kvs_perfc_fini(void);

merr_t
kvs_init(void);

void
kvs_fini(void);

void
kvs_cursor_perfc_free(struct perfc_set *pcs_cc, struct perfc_set *pcs_cd);

void
kvs_cursor_perfc_alloc(const char *dbname, struct perfc_set *pcs_cc, struct perfc_set *pcs_cd);

/**
 * struct cache_bucket - a list of cursors per rb_node
 * @node:     how we link into rb tree
 * @list:     list of cached cursors
 * @oldest:   insertion time (ns) of oldest cursor on %list
 * @cnt:      number of cursors on %list
 * @freeme:   if %true, bucket must be freed via %free()
 */
struct cache_bucket {
    struct rb_node          node;
    struct kvs_cursor_impl *list;
    u64                     oldest;
    int                     cnt;
    bool                    freeme;
};

struct curcache {
    struct mutex         cca_lock;
    struct rb_root       cca_root;
    struct cache_bucket *cca_bkt_head;
} HSE_ALIGNED(SMP_CACHE_BYTES * 2);

struct ikvs {
    uint             ikv_sfx_len;
    uint             ikv_pfx_len;
    struct c0 *      ikv_c0;
    struct cn *      ikv_cn;
    struct mpool *   ikv_ds;
    struct perfc_set ikv_pkvsl_pc; /* Public kvs interfaces Lat. */
    struct perfc_set ikv_cc_pc;
    struct perfc_set ikv_cd_pc;

    struct kvs_rparams ikv_rp;

    const char *ikv_kvs_name;
    const char *ikv_mpool_name;
    struct cache_bucket *ikv_curcache_bktmem;

    /* The width of the cursor cache divided by two should
     * yield a prime in order for ikvs_td2cca() to work well.
     */
    uint            ikv_curcache_preenidx;
    struct curcache ikv_curcachev[14];
};

void
ikvs_cursor_reap(struct ikvs *kvs);

void
ikvs_cursor_bkt_free(struct curcache *cca, struct cache_bucket *bkt);

void
kvs_cursor_perfc_fini(void);

merr_t
kvs_cursor_zone_alloc(void);

void
kvs_cursor_zone_free(void);

#if HSE_MOCKING
#include "kvs_ut.h"
#endif

#endif
