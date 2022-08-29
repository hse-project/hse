/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_IKVS_H
#define HSE_KVS_IKVS_H

#include <hse/error/merr.h>
#include <hse/util/arch.h>
#include <hse/util/list.h>
#include <hse/util/mutex.h>
#include <hse/util/perfc.h>

#include <hse/ikvdb/tuple.h>
#include <hse/ikvdb/kvdb_health.h>
#include <hse/ikvdb/kvs_rparams.h>
#include <hse/ikvdb/query_ctx.h>

#define TOMBSPAN_MIN_WIDTH 8

/* MTF_MOCK_DECL(kvs) */

/*- Internal Key Value Store  -----------------------------------------------*/

struct hse_kvdb_txn;
struct kvdb_ctxn;
struct kvdb_kvs;
struct cndb;
struct ikvdb;
struct ikvdb_impl;
struct mpool;
struct kvs_cparams;
struct lc;
struct cn;
struct cn_kvdb;
struct wal;
struct viewset;

struct kc_filter {
    const void *kcf_maxkey;
    size_t      kcf_maxklen;
};

struct hse_kvs_cursor {
    struct perfc_set *     kc_pkvsl_pc;
    struct kvdb_kvs *      kc_kvs;
    struct kvdb_ctxn_bind *kc_bind;
    uint64_t               kc_gen;
    uint64_t               kc_seq;
    uint64_t               kc_create_time;
    volatile bool          kc_on_list;
    unsigned int           kc_flags;
    merr_t                 kc_err;
    struct kc_filter       kc_filter;
    void *                 kc_viewcookie;
};

struct ikvs {
    uint64_t ikv_gen HSE_ACP_ALIGNED;
    uint64_t         ikv_cnid;
    uint             ikv_pfx_len;
    struct c0 *      ikv_c0;
    struct cn *      ikv_cn;
    struct lc *      ikv_lc;
    struct wal *     ikv_wal;
    struct perfc_set ikv_pkvsl_pc; /* Public kvs interfaces Lat. */
    struct perfc_set ikv_cc_pc;
    struct perfc_set ikv_cd_pc;

    struct kvs_rparams ikv_rp;

    const char *ikv_kvs_name;
};

/* kvs interfaces...
 */
merr_t
kvs_open(
    struct ikvdb *      kvdb,
    struct kvdb_kvs *   kvs,
    struct mpool *      ds,
    struct cndb *       cndb,
    struct lc *         lc,
    struct wal         *wal,
    struct kvs_rparams *rp,
    struct kvdb_health *health,
    struct cn_kvdb *    cn_kvdb,
    uint                kvs_oflags);

merr_t
kvs_close(struct ikvs *ikvs);

struct cn *
kvs_cn(struct ikvs *ikvs);

uint64_t
kvs_cnid(const struct ikvs *ikvs);

bool
kvs_txn_is_enabled(struct ikvs *kvs);

void
kvs_perfc_init(void) HSE_COLD;
void
kvs_perfc_fini(void) HSE_COLD;

merr_t
kvs_init(void) HSE_COLD;
void
kvs_fini(void) HSE_COLD;

/* kvs_cursor interfaces...
 */
merr_t
kvs_cursor_seek(
    struct hse_kvs_cursor *cursor,
    const void *           key,
    uint32_t               len,
    const void *           limit,
    uint32_t               limit_len,
    struct kvs_ktuple *    kt);

merr_t
kvs_cursor_read(struct hse_kvs_cursor *cursor, unsigned int flags, bool *eof);

void
kvs_cursor_key_copy(
    struct hse_kvs_cursor  *cursor,
    void                   *buf,
    size_t                  bufsz,
    const void            **key_out,
    size_t                 *klen_out);

merr_t
kvs_cursor_val_copy(
    struct hse_kvs_cursor  *cursor,
    void                   *buf,
    size_t                  bufsz,
    const void            **val_out,
    size_t                 *vlen_out);

void
kvs_cursor_perfc_alloc(
    uint                prio,
    const char         *dbname,
    struct perfc_set   *pcs_cc,
    struct perfc_set   *pcs_cd);

void
kvs_cursor_perfc_free(struct perfc_set *pcs_cc, struct perfc_set *pcs_cd);

void
kvs_cursor_perfc_init(void) HSE_COLD;
void
kvs_cursor_perfc_fini(void) HSE_COLD;

merr_t
kvs_curcache_init(void) HSE_COLD;
void
kvs_curcache_fini(void) HSE_COLD;

/* ikvs interfaces...
 */
struct perfc_set *
kvs_perfc_pkvsl(struct ikvs *ikvs);

merr_t
kvs_put(
    struct ikvs *            ikvs,
    struct hse_kvdb_txn *    txn,
    struct kvs_ktuple *      kt,
    struct kvs_vtuple       *vt,
    uint64_t                 seqno);

merr_t
kvs_get(
    struct ikvs *        ikvs,
    struct hse_kvdb_txn *txn,
    struct kvs_ktuple *  key,
    uint64_t             seqno,
    enum key_lookup_res *res,
    struct kvs_buf *     vbuf);

merr_t
kvs_del(struct ikvs *ikvs, struct hse_kvdb_txn *txn, struct kvs_ktuple *key, uint64_t seqno);

merr_t
kvs_pfx_probe(
    struct ikvs *        kvs,
    struct hse_kvdb_txn *txn,
    struct kvs_ktuple *  kt,
    uint64_t             seqno,
    enum key_lookup_res *res,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf);

merr_t
kvs_prefix_del(struct ikvs *ikvs, struct hse_kvdb_txn *txn, struct kvs_ktuple *key, uint64_t seqno);

void
kvs_maint_task(struct ikvs *ikvs, uint64_t now);

struct hse_kvs_cursor *
kvs_cursor_alloc(struct ikvs *ikvs, const void *prefix, size_t pfx_len, bool reverse);

void
kvs_cursor_free(struct hse_kvs_cursor *cursor);

merr_t
kvs_cursor_init(struct hse_kvs_cursor *cursor, struct kvdb_ctxn *ctxn);

merr_t
kvs_cursor_bind_txn(struct hse_kvs_cursor *handle, struct kvdb_ctxn *ctxn);

void
kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

void
kvs_cursor_reap(struct ikvs *kvs);

merr_t
kvs_cursor_update(struct hse_kvs_cursor *cursor, struct kvdb_ctxn *ctxn, uint64_t seqno);

/* kvdb_kvs interfaces...
 */

/* MTF_MOCK */
struct ikvdb_impl *
kvdb_kvs_parent(struct kvdb_kvs *kk);

/* MTF_MOCK */
struct kvs_cparams *
kvdb_kvs_cparams(struct kvdb_kvs *kk);

/* MTF_MOCK */
uint32_t
kvdb_kvs_flags(struct kvdb_kvs *kk);

/* MTF_MOCK */
uint64_t
kvdb_kvs_cnid(struct kvdb_kvs *kk);

/* MTF_MOCK */
const char *
kvdb_kvs_name(struct kvdb_kvs *kk);

/* MTF_MOCK */
void
kvdb_kvs_set_ikvs(struct kvdb_kvs *kk, struct ikvs *ikvs);

#if HSE_MOCKING
#include "kvs_ut.h"
#endif

#endif
