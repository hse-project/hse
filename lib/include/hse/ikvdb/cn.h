/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_IKVS_CN_H
#define HSE_IKVS_CN_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/kvdb_health.h>
#include <hse/ikvdb/kvs.h>
#include <hse/ikvdb/kvs_cparams.h>
#include <hse/ikvdb/limits.h>
#include <hse/ikvdb/tuple.h>
#include <hse/util/workqueue.h>

/* MTF_MOCK_DECL(cn) */

#define CN_CFLAG_CAPPED (1 << 0)

struct cn;
struct cn_kvdb;
struct cndb;
struct mpool;
struct kvs_cparams;
struct kvs_rparams;
struct kvset_mblocks;
struct kvdb_kvs;
struct sts;
struct mclass_policy;
enum cn_action;
enum hse_mclass;

/* MTF_MOCK */
merr_t
cn_open(
    struct cn_kvdb *cn_kvdb,
    struct mpool *mp,
    struct kvdb_kvs *kvs,
    struct cndb *cndb,
    uint64_t cnid,
    struct kvs_rparams *rp,
    const char *kvdb_home,
    const char *kvs_name,
    struct kvdb_health *health,
    uint flags,
    struct cn **cn_out);

/* MTF_MOCK */
merr_t
cn_close(struct cn *cn);

/* MTF_MOCK */
uint32_t
cn_cp2cflags(const struct kvs_cparams *cp);

/* MTF_MOCK */
bool
cn_is_capped(const struct cn *cn);

/* MTF_MOCK */
bool
cn_is_replay(const struct cn *cn);

/* MTF_MOCK */
void
cn_periodic(struct cn *cn, uint64_t now);

/* MTF_MOCK */
merr_t
cn_init(void);

/* MTF_MOCK */
void
cn_fini(void);

/* MTF_MOCK */
uint64_t
cn_get_ingest_dgen(struct cn *cn);

/* MTF_MOCK */
void
cn_inc_ingest_dgen(struct cn *cn);

/* MTF_MOCK */
struct kvs_rparams *
cn_get_rp(const struct cn *cn);

/* MTF_MOCK */
struct mpool *
cn_get_mpool(const struct cn *cn);

/* MTF_MOCK */
struct mclass_policy *
cn_get_mclass_policy(const struct cn *cn);

/* MTF_MOCK */
void
cn_disable_maint(struct cn *handle, bool onoff);

/*
 * Note: Tombstones indicated by:
 *     return value == hse_success && res == FOUND_TOMB
 */
/* MTF_MOCK */
merr_t
cn_get(
    struct cn *cn,
    struct kvs_ktuple *kt,
    uint64_t seq,
    enum key_lookup_res *res,
    struct kvs_buf *vbuf);

struct query_ctx;

merr_t
cn_pfx_probe(
    struct cn *cn,
    struct kvs_ktuple *kt,
    uint64_t seq,
    enum key_lookup_res *res,
    struct query_ctx *qctx,
    struct kvs_buf *kbuf,
    struct kvs_buf *vbuf);

/**
 * cn_ingestv() - A vectored version of cn_ingest
 * @cn:
 * @mbv:
 * @ingestid: passed by C1. Opaque to cndb. Stored in the cndb mdc. cndb replay
 *      returns to C1 the ingestid of the latest successful ingest.
 *      "latest" means the ingestid corresponding to the successful ingest
 *      with highest kvdb sequence number.
 * @ingestc:
 */
/* MTF_MOCK */
merr_t
cn_ingestv(
    struct cn **cn,
    struct kvset_mblocks **mbv,
    uint64_t *kvsetidv,
    uint ingestc,
    uint64_t ingestid,
    uint64_t txhorizon,
    uint64_t *min_seqno_out,
    uint64_t *max_seqno_out);

/* MTF_MOCK */
struct perfc_set *
cn_get_ingest_perfc(const struct cn *cn);

/* MTF_MOCK */
void *
cn_get_tree(const struct cn *cn);

/* MTF_MOCK */
uint64_t
cn_get_seqno_horizon(struct cn *cn);

/* MTF_MOCK */
void
cn_ref_get(struct cn *cn);

/* MTF_MOCK */
void
cn_ref_put(struct cn *cn);

void
cn_ref_wait(struct cn *cn);

/* MTF_MOCK */
struct workqueue_struct *
cn_get_io_wq(struct cn *cn);

/* MTF_MOCK */
struct workqueue_struct *
cn_get_maint_wq(struct cn *cn);

/* MTF_MOCK */
struct csched *
cn_get_sched(struct cn *cn);

/* MTF_MOCK */
atomic_int *
cn_get_cancel(struct cn *cn);

/* MTF_MOCK */
struct perfc_set *
cn_get_perfc(struct cn *cn, enum cn_action action);

/* MTF_MOCK */
struct perfc_set *
cn_pc_capped_get(struct cn *cn);

/* MTF_MOCK */
struct kvs_cparams *
cn_get_cparams(const struct cn *handle);

/* MTF_MOCK */
uint64_t
cn_get_cnid(const struct cn *cn);

/* MTF_MOCK */
struct cndb *
cn_get_cndb(const struct cn *cn);

/* MTF_MOCK */
struct cn_kvdb *
cn_get_cn_kvdb(const struct cn *handle);

/* MTF_MOCK */
uint32_t
cn_get_flags(const struct cn *handle);

/* MTF_MOCK */
uint64_t
cn_mpool_dev_zone_alloc_unit_default(struct cn *cn, enum hse_mclass mclass);

#if HSE_MOCKING
#include "cn_ut.h"
#endif /* HSE_MOCKING */

#endif
