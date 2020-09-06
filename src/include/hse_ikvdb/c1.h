/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_H
#define HSE_C1_H

#include <hse_util/platform.h>
#include <hse_util/slist.h>
#include <hse_util/bonsai_tree.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/c1_kvcache.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/limits.h>

#define HSE_C1_DEFAULT_STRIPE_WIDTH 4

/* MTF_MOCK_DECL(c1) */

struct kvb_builder_iter;
struct kvs_ktuple;
struct c1_kvbundle;
struct c1_kvtuple;
struct c1_vtuple;
struct c1;
struct c0sk;
struct kvdb_rparams;
struct ikvdb_c1_replay;
struct kvset_builder;
struct throttle_sensor;

struct mpool;

struct c1_config_info {
    int           c1_denabled;
    size_t        c1_dsize;
    size_t        c1_dcapacity;
    unsigned long c1_dtime;
};

enum c1_ingest_type {
    C1_INGEST_ASYNC,
    C1_INGEST_FLUSH,
    C1_INGEST_SYNC,
};

struct c1_bonsai_vbldr {
    struct kvset_builder *cbv_bldr;
    u64                   cbv_gen;
    u64                   cbv_blkid;
    u32                   cbv_blkidx;
    u32                   cbv_blkoff;
    u64                   cbv_blkvlen;
    u64                   cbv_blkval;
};

struct c1_kvinfo {
    u64 ck_kcnt;
    u64 ck_vcnt;
    u64 ck_kvsz;
};

struct c1_iterinfo {
    u32              ci_iterc;
    struct c1_kvinfo ci_iterv[HSE_C0_INGEST_WIDTH_MAX * 2];
    struct c1_kvinfo ci_total;
};

/**
 * c1_cningest_status() - Function to store cN ingest status into c1
 * @c1:                   Opaque c1 structure (returned by c1_open)
 * @seqno:                Sequence number for ingest operation
 * @status:               In progress or completed
 * @cnid:                 Unique CNID representing a kvs in kvdb
 * @kt:                   Last key tuple ingest into cN
 */
merr_t
c1_cningest_status(struct c1 *c1, u64 seqno, merr_t status, u64 cnid, const struct kvs_ktuple *kt);

/**
 * c1_alloc() - Allocates on-media structures for durability layer of KVDB
 * @ds:         Data store where the on-media structures are allocated
 * @cparams:    Creation time parameters such as durability time, size etc.
 * @oid1out:    First OID of c1 MDC
 * @oid2out:    Second OID of c1 MDC
 */
/* MTF_MOCK */
merr_t
c1_alloc(struct mpool *ds, struct kvdb_cparams *cparams, u64 *oid1out, u64 *oid2out);

/**
 * c1_make() - Formats on-media structures for durability layer of KVDB
 * @ds:        Data store where the on-media structures are allocated
 * @cparams:   Creation time parameters such as durability time, size etc.
 * @oid1out:   First OID of c1 MDC
 * @oid2out:   Second OID of c1 MDC
 */
/* MTF_MOCK */
merr_t
c1_make(struct mpool *ds, struct kvdb_cparams *cparams, u64 oid1, u64 oid2);

struct c1;

/**
 * c1_free()    - Removes all on-media structure created for durablity
 * @ds:           Data store where the on-media structures are allocated
 * @oid1out:      First OID of c1 MDC
 * @oid2out:      Second OID of c1 MDC
 */
/* MTF_MOCK */
merr_t
c1_free(struct mpool *ds, u64 oid1, u64 oid2);

/**
 * c1_open() - Opens c1 for reads and writes.
 *@rdonly:     Read-only mode
 *@oid1:       First OID of c1 MDC
 *@oid2:       Second OID of c1 MDC
 *@kvmsgen:    kvsmgen of last successful cn ingest
 *@mpname:     mpool name
 *@dbname:     kvdb name
 *@ikvdb:      internal kvdb handle for callbacks
 *@c0sk:       c0sk handle
 *@c1:         (output) c1 handle
 */
/* MTF_MOCK */
merr_t
c1_open(
    struct mpool *       ds,
    int                  rdonly,
    u64                  oid1,
    u64                  oid2,
    u64                  kvmsgen,
    const char *         mpname,
    struct kvdb_rparams *rparams,
    struct ikvdb *       ikvdb,
    struct c0sk *        c0sk,
    struct c1 **         out);

/**
 * c1_close() - Closes c1
 *@c1:          c1 handle
 */
/* MTF_MOCK */
merr_t
c1_close(struct c1 *c1);

/**
 * c1_ingest() - Performs ingests into c1.
 *@c1:           c1 handle
 *@iter:         Iterator to extract evey key/value to persist
 *@cki:          kv info
 *@ingestflag:   Type of ingest - async or sync.
 */
/* MTF_MOCK */
merr_t
c1_ingest(struct c1 *c1, struct kvb_builder_iter *iter, struct c1_kvinfo *cki, int ingestflag);

/**
 * c1_txn_begin() - Beginning of a c1 transaction
 *@c1:    c1 handle
 *@txnid: Unique transaction identifier.
 *@ci:    c1 iter info
 *@flag:  Reserved for combining sync and async txs in future.
 */
/* MTF_MOCK */
merr_t
c1_txn_begin(struct c1 *c1, u64 txnid, struct c1_iterinfo *ci, int flag);

/**
 * c1_txn_commit() - Commits  a c1 transaction
 *@c1:               c1 handle
 *@txnid:            Unique transaction identifier.
 *@flag:             Reserved for combining sync and async txs in future.
 */
/* MTF_MOCK */
merr_t
c1_txn_commit(struct c1 *c1, u64 txnid, u64 seqno, int flag);

/**
 * c1_txn_commit() - Aborts a c1 transaction
 *@c1:               c1 handle
 *@txnid:            Unique transaction identifier.
 */
/* MTF_MOCK */
merr_t
c1_txn_abort(struct c1 *c1, u64 txnid);

/**
 * c1_sync() - Synchronous flush function for c1.
 *@c1:         c1 handle
 */
/* MTF_MOCK */
merr_t
c1_sync(struct c1 *c1);

/**
 * c1_flush() - Asynchronous flush function for c1.
 *@c1:          c1 handle
 */
/* MTF_MOCK */
merr_t
c1_flush(struct c1 *c1);

/**
 * c1_ingest_stripsize() - Returns the preferred size for c1 ingests.
 *@c1:                     c1 handle
 */
/* MTF_MOCK */
u64
c1_ingest_stripsize(struct c1 *c1);

/**
 * c1_ingest_space_threshold() - Returns c1 ingest space threshold
 * @c1: c1 handle
 */
u64
c1_ingest_space_threshold(struct c1 *c1);

/**
 * c1_config_info - get durablity information
 * @c1:       Opaque c1 structure (returned by c1_open)
 * @info:     (output) durablity information
 */
merr_t
c1_config_info(struct c1 *c1, struct c1_config_info *info);

/**
 * c1_get_kvcache - Get the next available kvcache instance from c1.
 * @c1:             c1 handle
 */
struct c1_kvcache *
c1_get_kvcache(struct c1 *c1h);

/**
 * c1_put_kvcache - put a c1_kvcache handle
 * @c1:             c1 handle
 */
void
c1_put_kvcache(struct c1_kvcache *c1h);

/**
 * c1_kvbundle_alloc - Allocate a kv bundle
 * @cc:               c1 kvcache handle
 * @ckvb:             kvbundle handle (output)
 */
merr_t
c1_kvbundle_alloc(struct c1_kvcache *cc, struct c1_kvbundle **ckvb);

/**
 * c1_kvbundle_add_kvt - Add a kvtuple to the specified kv bundle
 * @ckvb: kvbundle handle
 * @ckvt:
 * @tail:
 */
void
c1_kvbundle_add_kvt(struct c1_kvbundle *ckvb, struct c1_kvtuple *ckvt, struct s_list_head **tail);

/**
 * c1_kvbundle_set_seqno - Set the min and max seqno for this kv bundle
 * @ckvb: kvbundle handle
 * @minseqno:
 * @maxseqno:
 */
void
c1_kvbundle_set_seqno(struct c1_kvbundle *ckvb, u64 minseqno, u64 maxseqno);

/**
 * c1_kvbundle_set_size - Set the kvbundle size
 * @ckvb: kvbundle handle
 * @size:
 */
void
c1_kvbundle_set_size(struct c1_kvbundle *ckvb, u64 size);

/**
 * c1_kvbundle_get_ktc - Get the number of ktuples in a kvbundle
 * @ckvb: kvbundle handle
 */
u32
c1_kvbundle_get_ktc(struct c1_kvbundle *ckvb);

/**
 * c1_kvbundle_get_vtc - Get the number of vtuples in a kvbundle
 * @ckvb: kvbundle handle
 */
u32
c1_kvbundle_get_vtc(struct c1_kvbundle *ckvb);

/**
 * c1_kvtuple_alloc - Allocate a c1 kvtuple element
 * @cc:   c1 kvcache reference
 * @ckvt: c1 kvtuple (output)
 */
merr_t
c1_kvtuple_alloc(struct c1_kvcache *cc, struct c1_kvtuple **ckvt);

/**
 * c1_kvtuple_init - Initialize a c1 kvtuple element
 * @ckvt: c1 kvtuple handle
 * @klen:
 * @data:
 * @index:
 * @bkv:
 */
void
c1_kvtuple_init(
    struct c1_kvtuple *ckvt,
    u64                klen,
    void *             data,
    u64                cnid,
    u32                skidx,
    struct bonsai_kv * bkv);

/**
 * c1_kvtuple_addval - Add value to a c1 kvtuple
 * @ckvt: c1 kvtuple handle
 * @cvt:
 * @tail:
 */
void
c1_kvtuple_addval(struct c1_kvtuple *ckvt, struct c1_vtuple *cvt, struct s_list_head **tail);

/**
 * c1_vtuple_alloc - Allocate a c1 vtuple element
 * @cc:   c1 kvcache reference
 * @cvt: c1 vtuple (output)
 */
merr_t
c1_vtuple_alloc(struct c1_kvcache *cc, struct c1_vtuple **cvt);

/**
 * c1_vtuple_init - Initialize a c1 vtuple element
 * @ckvt: c1 vtuple handle
 * @vlen:
 * @seqno:
 * @data:
 * @tomb:
 * @vbuilder:
 */
void
c1_vtuple_init(
    struct c1_vtuple *       cvt,
    u64                      vlen,
    u64                      seqno,
    void *                   data,
    bool                     tomb,
    struct c1_bonsai_vbldr **vbuilder);

/**
 * c1_is_clean -
 * @c1: c1 handle
 */
/* MTF_MOCK */
bool
c1_is_clean(struct c1 *c1);

/**
 * c1_ikvdb - returns ikvdb handle
 * @c1:       c1 handle
 */
/* MTF_MOCK */
struct ikvdb *
c1_ikvdb(struct c1 *c1);

/**
 * c1_get_txnid - get the next c1 transaction ID
 * @c1: c1 handle
 */
u64
c1_get_txnid(struct c1 *c1);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
