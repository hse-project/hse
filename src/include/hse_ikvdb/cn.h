/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVS_CN_H
#define HSE_IKVS_CN_H

#include <hse_util/hse_err.h>
#include <hse_util/workqueue.h>

#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvs.h>

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
enum cn_action;
enum mp_media_classp;

enum cn_aio_reqtype {
    CN_AIO_REQ_INGEST = 0,
    CN_AIO_REQ_MAINT,
    CN_AIO_REQ_MAX,
};

/* MTF_MOCK */
merr_t
cn_make(struct mpool *ds, struct kvs_cparams *cp, struct kvdb_health *health);

/* MTF_MOCK */
merr_t
cn_open(
    struct cn_kvdb *    cn_kvdb,
    struct mpool *      mp_dataset,
    struct kvdb_kvs *   kvs,
    struct cndb *       cndb,
    u64                 cnid,
    struct kvs_rparams *rp,
    const char *        mp_name,
    const char *        kvs_name,
    struct kvdb_health *health,
    uint                flags,
    struct cn **        cn_out);

/* MTF_MOCK */
merr_t
cn_close(struct cn *cn);

/* MTF_MOCK */
u32
cn_cp2cflags(struct kvs_cparams *cp);

/* MTF_MOCK */
bool
cn_is_capped(const struct cn *cn);

/* MTF_MOCK */
bool
cn_get_mblk_sync_writes(const struct cn *cn);

/* MTF_MOCK */
bool
cn_is_closing(const struct cn *cn);

/* MTF_MOCK */
bool
cn_is_replay(const struct cn *cn);

/* MTF_MOCK */
void
cn_periodic(struct cn *cn, u64 now);

/* MTF_MOCK */
merr_t
cn_init(void);

/* MTF_MOCK */
void
cn_fini(void);

/* MTF_MOCK */
u64
cn_get_ingest_dgen(const struct cn *cn);

/* MTF_MOCK */
struct kvs_rparams *
cn_get_rp(const struct cn *cn);

/* MTF_MOCK */
struct mpool *
cn_get_dataset(const struct cn *cn);

/* MTF_MOCK */
struct tbkt *
cn_get_tbkt_maint(const struct cn *cn);

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
    struct cn *          cn,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct kvs_buf *     vbuf);

struct query_ctx;

merr_t
cn_pfx_probe(
    struct cn *          cn,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct query_ctx *   qctx,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf);

/**
 * cn_ingestv() - A vectored version of cn_ingest
 * @cn:
 * @mbv:
 *      The first vcommitted[i] vblocks of kvset mbv[i] are already committed.
 * @mbc:
 * @vcommitted: indicated in each kvset how many vblocks are already committed.
 *      Also these comitted vblocks ae not deleted by cndb replay [in the case
 *      this ingest is rolled back].
 *      Number of elements is ingestc.
 * @ingestid: passed by C1. Opaque to cndb. Stored in the cndb mdc. cndb replay
 *      returns to C1 the ingestid of the latest successful ingest.
 *      "latest" means the ingestid corresponding to the successful ingest
 *      with highest kvdb sequence number.
 * @ingestc:
 * @ingested:
 * @seqno_max_out:
 */
/* MTF_MOCK */
merr_t
cn_ingestv(
    struct cn **           cn,
    struct kvset_mblocks **mbv,
    int *                  mbc,
    u32 *                  vcommitted,
    u64                    ingestid,
    int                    ingestc,
    bool *                 ingested_out,
    u64 *                  seqno_max_out);

/* MTF_MOCK */
struct perfc_set *
cn_get_ingest_perfc(const struct cn *cn);

/* MTF_MOCK */
void *
cn_get_tree(const struct cn *cn);

/* MTF_MOCK */
u64
cn_get_seqno_horizon(struct cn *cn);

/* MTF_MOCK */
void
cn_ref_get(struct cn *cn);

/* MTF_MOCK */
void
cn_ref_put(struct cn *cn);

/* MTF_MOCK */
u64
cn_hash_get(const struct cn *cn);

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
atomic_t *
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
size_t
cn_get_sfx_len(struct cn *cn);

/* MTF_MOCK */
u64
cn_get_cnid(const struct cn *cn);

/* MTF_MOCK */
struct cndb *
cn_get_cndb(const struct cn *cn);

/* MTF_MOCK */
struct cn_kvdb *
cn_get_cn_kvdb(const struct cn *handle);

/* MTF_MOCK */
u32
cn_get_flags(const struct cn *handle);

/* MTF_MOCK */
unsigned
cn_best_ingest_count(const struct cn *cn, unsigned avg_key_len);

void *
cn_aio_alloc(struct cn *cn, size_t sz, bool ingest, bool force);

void
cn_aio_free(struct cn *cn, void *buf, size_t sz, bool ingest);

/* MTF_MOCK */
u64
cn_vma_mblock_max(struct cn *cn, enum mp_media_classp mclass);

/* MTF_MOCK */
u64
cn_mpool_dev_zone_alloc_unit_default(struct cn *cn, enum mp_media_classp mclass);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "cn_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
