/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CNDB_INTERNAL_H
#define HSE_KVS_CNDB_INTERNAL_H

#include <hse/limits.h>

#include <hse_util/platform.h>
#include <hse_util/mutex.h>

#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs_cparams.h>

#include "cndb_omf.h"

struct mpool_mdc;
struct mpool;

/* [HSE_REVISIT] Eventually, these values should be automatically tuned for each
 * cndb based on the size of the mpool and the fanout bits.
 */
#define CNDB_KVSETS_L1 (8)
#define CNDB_KVSETS_L2 (8 * CNDB_KVSETS_L1)
#define CNDB_KVSETS_L3 (8 * CNDB_KVSETS_L2)
#define CNDB_KVSETS_L4 (8 * CNDB_KVSETS_L3)

#define CNDB_KVSETS_L1_V1 (8)
#define CNDB_KVSETS_L2_V1 (8 * CNDB_KVSETS_L1_V1)
#define CNDB_KVSETS_L3_V1 (8 * CNDB_KVSETS_L2_V1)
#define CNDB_KVSETS_L4_V1 (8 * CNDB_KVSETS_L3_V1)

/* Multiplied by 2 because a kvset requires txc,txm records and multiplied by 2
 * again because a complete txn describing a kvset also requires tx, ack-C.
 *
 * This number is 18,720.  We will use this to allocate 2 arrays of pointers,
 * and an additional transient array (during compaction), for a total of 150KiB.
 *
 * The footprint beyond this will depend on the number of transactions and the
 * number of keys in each kvset.
 *
 */
#define CNDB_ENTRIES \
    (4 * 4 * 2 * 2 * (CNDB_KVSETS_L1 + CNDB_KVSETS_L3 + CNDB_KVSETS_L2 + CNDB_KVSETS_L4))
#define CNDB_WORKC_MARGIN_DEFAULT 1024

/* Maximum reclen is currently based on a C record, with 3500 blockids. */
#define CNDB_CBUFSZ_DEFAULT (sizeof(struct cndb_txc_omf) + (sizeof(u64) * 3500))
#define CNDB_CAPTGT_DEFAULT (CNDB_ENTRIES * CNDB_CBUFSZ_DEFAULT / 4)
#define CNDB_HIGH_WATER(c)  ((c)->cndb_captgt * 3 / 4)

struct cndb_cn {
    struct kvs_cparams cn_cp;
    u32                cn_flags;
    u32                cn_refcnt;
    u64                cn_cnid;
    size_t             cn_cbufsz;
    bool               cn_removed;
    char               cn_name[CNDB_CN_NAME_MAX];

    /* cn_cbuf is used to format updated info records. At all times, it
     * contains the most recent metadata at index [1].
     *
     * Therefore: metasz = cn_cbufsz - sizeof(cndb_info_omf)
     */
    struct cndb_info_omf *cn_cbuf;
};

/**
 * cndb_cn_initializer() - Only used in tests
 */
struct cndb_cn
cndb_cn_initializer(unsigned int fanout_bits, unsigned int pfx_len, u64 cnid);

struct cndb_idx {
    u64              cdx_tag;
    struct cndb_tx * cdx_tx;
    struct cndb_txc *cdx_txc;
    struct cndb_txm *cdx_txm;
    struct cndb_ack *cdx_ack;
    bool             cdx_full; /* whether txn is complete */
};

/**
 * struct cndb_ingest_replay()
 * @cir_ingestid:
 * @cir_txid:
 * @cir_success: true is the ingest whose id is above succeeded.
 *      false if the ingest has been rolled back durig cndb replay.
 */
struct cndb_ingest_replay {
    u64  cir_ingestid;
    u64  cir_txhorizon;
    u64  cir_txid;
    bool cir_success;
};

/**
 * struct cndb - one such structure per KVDB
 *
 * Lock order:
 *      cndb_cnv_lock then
 *      cndb_lock
 *
 * @cndb_lock: serialize:
 *      - appends in cndb mdc
 *      - rollover/compaction
 *      - creation/instantiation of a new CN for a new KVS
 *      - assignment of cndb_buf
 *      - update to cndb->cndb_read_only
 * @cndb_mdc:
 * @cndb_ds:
 * @cndb_kvdb_health:
 * @cndb_seqno:
 * @cndb_version: version of the cndb mdc content when it was read.
 *  Updated last time the cndb mdc was read.
 *  This is NOT the version at which this binary is writing in the cndb mdc.
 *  When writing in the cndb mdc, it is always at the lastest version
 *  (aka CNDB_VERSION).
 * @cndb_read_only:
 * @cndb_compacted:
 * @cndb_txid:
 * @cndb_captgt:
 * @cndb_high_water:
 * @cndb_oid1:
 * @cndb_oid2:
 * @cndb_refcnt: protected by cndb_lock
 *      Number of open KVSes. 0 during cndb replay.
 *
 * The four fields below are protected by cndb_lock.
 * @cndb_keepc: number of populated elements in cndb_keepv[]
 * @cndb_keepv: one entry per omf record. But entries are NOT in omf format.
 *      Entries are pointers to union cndb_mtu
 *      Contains metadata for all the KVSes of the KVDB.
 *      Used as the source to write in the cndb mdc.
 *      It is the output of a compaction, when the compaction starts
 *      cndb_keepv[] is empty.
 * @cndb_workc: number of populated elements in cndb_workv[].
 * @cndb_workv: one entry per omf record. But entries are NOT in omf format.
 *      Entries are pointers to union cndb_mtu
 *      Contains metadata for all the KVSes of the KVDB.
 *      Record append (_cndb_journal()) are going at the end of cndb_workv[].
 *      cndb_workv[] is the input for the compaction.
 *      When the compaction is done cndb_workv[] is empty.
 *
 * @cndb_entries:
 * @cndb_min_entries:
 * @cndb_workc_margin:
 * @cndb_entries_high_water:
 * @cndb_tagc:
 * @cndb_tagv:
 * @cndb_cnv_lock: serialize:
 *      - creation/instantiation of a CN of a new KVS
 *      - KVS drop
 *      - access to the table of KVSes CNs: cndb_cnv[] and cndb_cnc
 *      - CN id generator: cndb_cnid
 * @cndb_cnv:    protected by cndb_cnv_lock
 * @cndb_cnc:    protected by cndb_cnv_lock
 * @cndb_cnid:   protected by cndb_cnv_lock
 * @cndb_cbufsz: protected by cndb_lock
 * @cndb_cbuf:   protected by cndb_lock
 * @cndb_ing_rep: used to determine the id of the last successful ingest.
 *
 * The id of the last successful ingest (stored in cndb_ing_rep) is
 * passed to available at the end of cndb replay.
 * cndb_ing_rep is used only during cndb replay.
 */
struct cndb {
    struct mutex              cndb_lock;
    struct mpool_mdc *        cndb_mdc;
    struct mpool *            cndb_ds;
    struct kvdb_health *      cndb_kvdb_health;
    atomic64_t *              cndb_ikvdb_seqno;
    u64                       cndb_seqno;
    u16                       cndb_version;
    bool                      cndb_read_only;
    bool                      cndb_compacted;
    atomic64_t                cndb_txid;
    u64                       cndb_captgt;
    u64                       cndb_high_water;
    u64                       cndb_oid1;
    u64                       cndb_oid2;
    int                       cndb_refcnt;
    size_t                    cndb_keepc;
    void **                   cndb_keepv;
    size_t                    cndb_workc;
    void **                   cndb_workv;
    size_t                    cndb_entries;
    size_t                    cndb_min_entries;
    size_t                    cndb_workc_margin;
    size_t                    cndb_entries_high_water;
    size_t                    cndb_tagc;
    struct cndb_idx **        cndb_tagv;
    struct mutex              cndb_cnv_lock;
    struct cndb_cn *          cndb_cnv[HSE_KVS_COUNT_MAX]; /* cnv_lock */
    int                       cndb_cnc;                    /* cnv_lock */
    u64                       cndb_cnid;                   /* cnv_lock */
    size_t                    cndb_cbufsz;
    void *                    cndb_cbuf;
    struct cndb_ingest_replay cndb_ing_rep;
    struct kvdb_rparams *     cndb_rp;
};

/* in-memory counterparts to cndb structures */
struct cndb_oid {
    u64 mmtx_oid;
};

struct cndb_hdr {
    u32 mth_type;
};

struct cndb_ver {
    struct cndb_hdr hdr;
    u32             mtv_magic;
    u32             mtv_version;
    u64             mtv_captgt;
};

struct cndb_meta {
    struct cndb_hdr hdr;
    u64             mte_seqno_max;
};

struct cndb_info {
    struct cndb_hdr hdr;
    u32             mti_sfx_len;
    u32             mti_fanout_bits;
    u32             mti_prefix_len;
    u32             mti_prefix_pivot;
    u32             mti_flags;
    u64             mti_cnid;
    size_t          mti_metasz;
    char            mti_name[CNDB_CN_NAME_MAX];
    char            mti_meta[];
};

struct cndb_tx {
    struct cndb_hdr hdr;
    u64             mtx_id;
    u32             mtx_nc;
    u32             mtx_nd;
    u64             mtx_seqno;
    u64             mtx_ingestid;
    u64             mtx_txhorizon;
};

/**
 * struct cndb_txc - memory image  of omf record cndb_txc_omf
 * @hdr:
 * @mtc_cnid:
 * @mtc_id:
 * @mtc_tag:
 * @mtc_keepvbc: number of vblocks to keep (NOT to delete in case the CN
 *      mutation is rolled back).
 * @mtc_kcnt:
 * @mtc_vcnt:
 * an array of mtc_kcnt mblock OIDs appears here
 * an array of mtc_vcnt mblock OIDs appears here. The vblocks to keep are first.
 */
struct cndb_txc {
    struct cndb_hdr hdr;
    u64             mtc_cnid;
    u64             mtc_id;
    u64             mtc_tag;
    u32             mtc_keepvbc;
    u32             mtc_kcnt;
    u32             mtc_vcnt;
};

struct cndb_txm {
    struct cndb_hdr hdr;
    u64             mtm_cnid;
    u64             mtm_id;
    u64             mtm_tag;
    u32             mtm_level;
    u32             mtm_offset;
    u64             mtm_dgen;
    u64             mtm_vused;
    u32             mtm_compc;
    u32             mtm_scatter;
};

struct cndb_txd {
    struct cndb_hdr hdr;
    u64             mtd_cnid;
    u64             mtd_id;
    u64             mtd_tag;
    u32             mtd_n_oids;
    /* an array of mtd_n_oids mblock OIDs appears here */
};

struct cndb_ack {
    struct cndb_hdr hdr;
    u64             mta_txid;
    u32             mta_type;
    u64             mta_tag;  /* unused for CNDB_ACK_TYPE_C */
    u64             mta_cnid; /* unused for CNDB_ACK_TYPE_C */
};

struct cndb_nak {
    struct cndb_hdr hdr;
    u64             mtn_txid;
};

union cndb_mtu {
    struct cndb_hdr  h;
    struct cndb_ver  v;
    struct cndb_meta e;
    struct cndb_info i;
    struct cndb_tx   x;
    struct cndb_txc  c;
    struct cndb_txm  m;
    struct cndb_txd  d;
    struct cndb_ack  a;
    struct cndb_nak  n;
};

enum {
    CNDB_OPEN_RDONLY = true,
    CNDB_OPEN_RDWR = false,
};

/* fault injection:
 *
 * [HSE_REVISIT] consider re-working this so a wider audience can use it.
 *
 * rparams is straightforward.  data tree has race conditions: starting a
 * program, then manipulating its data tree before it encounters a desired probe
 * is difficult.
 *
 *  Trigger Types:
 *
 * NFAULT_TRIG_NONE:     do not trigger.
 * NFAULT_TRIG_ONESHOT:  do when odometer == value
 * NFAULT_TRIG_PERIOD:   do when (odometer % value ) == 0
 * NFAULT_TRIG_LEVEL:    do when odometer >= value
 */
enum { NFAULT_TRIG_NONE, NFAULT_TRIG_ONESHOT, NFAULT_TRIG_PERIOD, NFAULT_TRIG_LEVEL };

struct nfault_trig {
    int trig_type;
    u64 trig_value;
};

struct nfault_probe {
    u64                probe_odometer;
    struct nfault_trig probe_trigger;
};

enum {
    CNDB_PROBE_DROP_TX,
    CNDB_PROBE_DROP_ACKC,
    CNDB_PROBE_DROP_ACKD,
    CNDB_PROBE_DROP_NAK,
    CNDB_PROBE_DROP_TXC,
    CNDB_PROBE_DROP_TXM,
    CNDB_PROBE_DROP_TXD,
    CNDB_NUM_PROBES
};

/*
 * Macros and prototypes for cndb mdc content upgrade.
 */

/**
 * cndb_unpack_fn - prototype of unpack functions.
 * @omf: input, record coming from cndb mdc.
 * @ver: CNDB version of the binary that appended this record in the CNDB mdc.
 * @mtu: output, unpacked record.
 *  If NULL, the caller doesn't want unpacking but wants the length of the
 *  "mtu" buffer that will receive the unpacking output. In that case plen must
 *  be not NULL.
 *  If not NULL, buffer receiving the record unpacking output.
 * @plen:
 *  If mtu is NULL, plen must not be NULL and *plen is set to the length of the
 *  "mtu" buffer that will receive the unpacking output.
 *  If mtu is not NULL, plen can be NULL or if not NULL it contains the length
 *  of the mtu buffer.
 *
 * This function works in two modes and usually is called twice (once in
 * each mode) for each record to unpack. It is called first to know the length
 * of the "mtu" buffer that will receive the output of the unpacking, and then
 * it is called a second time to do the unpacking.
 */
typedef merr_t
cndb_unpack_fn(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen);

/**
 * struct cndb_upg_history
 * @uh_fn: an unpacking function
 * @uh_ver: the first/oldest cndb version that generated records "uh_fn"
 *  can unpack. In other words, cndb version "uh_ver" was the first version
 *  to generate records "uh_fn" can unpack.
 *
 */
struct cndb_upg_history {
    cndb_unpack_fn *uh_fn;
    u32             uh_ver;
};

/**
 * struct cndb_upg_histlen
 * @uhl_his: table of unpacking functions for a particular type of record
 *  The oldest unpacking function is first in the table.
 * @uhl_len: number of elements in the table.
 */
struct cndb_upg_histlen {
    struct cndb_upg_history *uhl_his;
    u32                      uhl_len;
};

/**
 * cndb_unpack_get_fn() - get and return the right unpack function
 * @upghl:
 * @cndb_version:
 *
 * Look up the table "upghl" to find the unpack function corresponding
 * to the cndb_version passed in.
 * The function returned is the one in the table having the highest version
 * (uh_ver) being <= cndb_version passed in.
 */
cndb_unpack_fn *
cndb_unpack_get_fn(struct cndb_upg_histlen *upghl, u32 cndb_version);

/**
 * omf_cndb_ver_unpack() - unpack record CNDB_TYPE_VERSION
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_ver_unpack;
cndb_unpack_fn omf_cndb_meta_unpack;
cndb_unpack_fn omf_cndb_info_unpack_v4;
cndb_unpack_fn omf_cndb_info_unpack_v6;

/**
 * omf_cndb_info_unpack() - unpack record CNDB_TYPE_INFO and CNDB_TYPE_INFOD
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_info_unpack;
cndb_unpack_fn omf_cndb_info_unpack_v7;
cndb_unpack_fn omf_cndb_info_unpack_v9;

/**
 * omf_cndb_tx_unpack_v4() - unpack record CNDB_TYPE_TX V4
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_tx_unpack_v4;

/**
 * omf_cndb_tx_unpack_v5() - unpack record CNDB_TYPE_TX V5
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_tx_unpack_v5;

/**
 * omf_cndb_tx_unpack() - unpack record CNDB_TYPE_TX
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_tx_unpack;

/**
 * omf_cndb_txc_unpack() - unpack record CNDB_TYPE_TXC for cndb mdc version 4
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_txc_unpack_v4;

/**
 * omf_cndb_txc_unpack() - unpack record CNDB_TYPE_TXC
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_txc_unpack;

/**
 * omf_cndb_txm_unpack() - unpack record CNDB_TYPE_TXM
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_txm_unpack;
cndb_unpack_fn omf_cndb_txm_unpack_v8;

/**
 * omf_cndb_txd_unpack() - unpack record CNDB_TYPE_TXD
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_txd_unpack;

/**
 * omf_cndb_ack_unpack() - unpack record CNDB_TYPE_ACK
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_ack_unpack;

/**
 * omf_cndb_nak_unpack() - unpack record CNDB_TYPE_NAK
 *
 * See cndb_unpack_fn definition for parameters explanation.
 */
cndb_unpack_fn omf_cndb_nak_unpack;

/* MTF_MOCK_DECL(cndb_internal) */
int
nfault_probe(struct nfault_probe *probes, int id);

void
cndb_validate_vector(void **v, size_t c);

/* MTF_MOCK */
merr_t
cndb_cnv_get(struct cndb *cndb, u64 cnid, struct cndb_cn **cn_out);

/* PRIVATE */
merr_t
cndb_cnv_del(struct cndb *cndb, int idx);

void
cndb_set_hdr(struct cndb_hdr_omf *hdr, int type, int len);

/**
 * omf2len() - compute the size of the memory image (a mtu) of a cndb record
 *      from the cndb omf record.
 * @omf:
 * @cndb_version: cndb version of the cndb mdc containing this omf record.
 *  Used to select the right unpack function.
 * @len: output
 */
merr_t
omf2len(void *omf, u32 cndb_version, u32 *len);

/**
 * mtx2omf() - format an input mtu in a cndb mdc record (omf).
 * @cndb:
 * @omf: output
 * @mtu: input
 */
merr_t
mtx2omf(struct cndb *cndb, void *omf, union cndb_mtu *mtu);

/**
 * omf2mtx() - unpack a cndb mdc record.
 * @mtu: output
 * @mtulen: length of output buffer
 * @omf: input, the record
 * @cndb_version: cndb version of the cndb mdc containing this omf record.
 *  Used to select the right unpack function.
 *  function.
 */
merr_t
omf2mtx(union cndb_mtu *mtu, u32 *mtulen, void *omf, unsigned cndb_version);

/**
 * cndb_cnv_add() - add a cn to cndb
 * @cndb:   the cndb
 * @flags:  flags for the cn
 * @cp:     create-time parameters for the cn
 * @cnid:   unique identifier for this cn
 * @name:   name of the cn
 * @metasz: size of opaque metadata (can be zero)
 * @meta:   opaque metadata
 */
merr_t
cndb_cnv_add(
    struct cndb *             cndb,
    u32                       flags,
    const struct kvs_cparams *cp,
    u64                       cnid,
    const char *              name,
    size_t                    metasz,
    void *                    meta);

/**
 * cndb_import_md() - unpack a cndb mdc record and place the output in
 *  in cndb_workv[].
 * @cndb:
 * @buf: input, cndb mdc record. Should not be a CNDB_TYPE_VERSION.
 * @mtu: output, allocated  buffer containing cndb mdc record converted
 *  to in memory image. If record type is CNDB_TYPE_INFO[D], then mtu
 *  is returned NULL.
 */
merr_t
cndb_import_md(struct cndb *cndb, struct cndb_hdr_omf *buf, union cndb_mtu **mtu);

u64
mtxcnid(union cndb_mtu *mtu);

u64
mtxtag(union cndb_mtu *mtu);

u64
mtxid(union cndb_mtu *mtu);

int
cndb_cmp(const void *a, const void *b);

merr_t
cndb_tagalloc(struct cndb *cndb, struct cndb_txc *txc, struct cndb_tx *tx, bool full);

merr_t
cndb_tagdel(struct cndb *cndb, u64 tag);

merr_t
cndb_tagack(struct cndb *cndb, u64 tag, struct cndb_ack *ack);

merr_t
cndb_tagmeta(struct cndb *cndb, struct cndb_txm *txm);

merr_t
cndb_blkdel(struct cndb *cndb, union cndb_mtu *mtu, u64 txid);

/**
 * cndb_compact() - compact cndb metadata
 *
 * This function does NOT write in the cndb mdc, the writing is done by
 * cndb_rollover() calling this function.
 * The input of this function in cndb_workv[] only.
 * As a consequence this function doesn't handle CNDB_TYPE_INFO[D] records.
 *
 * @cndb:
 */
merr_t
cndb_compact(struct cndb *cndb);

merr_t
cndb_init(
    struct cndb *       cndb,
    struct mpool *      ds,
    bool                rdonly,
    atomic64_t *        ikvdb_seqno,
    size_t              cndb_entries,
    u64                 oid1,
    u64                 oid2,
    struct kvdb_health *health,
    struct kvdb_rparams *rp);

/**
 * cndb_get_ingestid()
 * @cndb:
 * @tx:
 *
 * Update the latest ingestid based on the value of the new
 * comer found in the CNDB_TYPE_TX record.
 * The ingestids are NOT always increasing. A more recent ingest may have
 * an ingest id smaller that the one of a older ingest.
 */
void
cndb_get_ingestid(struct cndb *cndb, struct cndb_tx *tx);

/**
 * cndb_record_unpack() - unpack a cndb mdc record.
 * @cndb_version: version of the cndb mdc being read.
 * @buf: points to the mdc record.
 * @mtu: unpacking output. Allocated by this function, the caller is
 *  responsible to free if *mtu is returned not NULL.
 *  If no error is returned *mtu is not NULL.
 */
merr_t
cndb_record_unpack(u32 cndb_version, struct cndb_hdr_omf *buf, union cndb_mtu **mtu);

#endif

#define CNDB_LOG_E(err, cndb, pri, fmt, ...)    \
    do {                                        \
        void *av[] = { &err, 0 };               \
                                                \
        log_pri(                                \
            pri,                                \
            "cndb (%lx, %lx) " fmt ": @@e",     \
            true,                               \
            av,                                 \
            (ulong)(cndb)->cndb_oid1,           \
            (ulong)(cndb)->cndb_oid2,           \
            ##__VA_ARGS__);                     \
    } while (0)

#define CNDB_LOG_NE(cndb, pri, fmt, ...)        \
    log_pri(                                    \
        pri,                                    \
        "cndb (%lx, %lx) " fmt,                 \
        true,                                   \
        NULL,                                   \
        (ulong)(cndb)->cndb_oid1,               \
        (ulong)(cndb)->cndb_oid2,               \
        ##__VA_ARGS__)

#define CNDB_LOG(err, cndb, pri, fmt, ...)                                              \
    do {                                                                                \
        if (err) {                                                                      \
            merr_t e = (err);                                                           \
                                                                                        \
            CNDB_LOG_E(e, cndb, pri, fmt, ##__VA_ARGS__);                               \
        } else if ((cndb) && (!(cndb)->cndb_rp || (cndb)->cndb_rp->cndb_debug)) {       \
            CNDB_LOG_NE(cndb, pri, fmt, ##__VA_ARGS__);                                 \
        }                                                                               \
    } while (0)

#define CNDB_LOG_DEBUG(_err, _cndb, _fmt, ...) \
    CNDB_LOG((_err), (_cndb), HSE_LOGPRI_DEBUG, _fmt, ##__VA_ARGS__)

#define CNDB_LOG_INFO(_err, _cndb, _fmt, ...) \
    CNDB_LOG((_err), (_cndb), HSE_LOGPRI_INFO, _fmt, ##__VA_ARGS__)

#define CNDB_LOG_WARN(_err, _cndb, _fmt, ...) \
    CNDB_LOG((_err), (_cndb), HSE_LOGPRI_WARN, _fmt, ##__VA_ARGS__)

#define CNDB_LOG_ERR(_err, _cndb, _fmt, ...) \
    CNDB_LOG((_err), (_cndb), HSE_LOGPRI_ERR, _fmt, ##__VA_ARGS__)

/* use e.g., CNDB_LOGTX(err, cndb, txid, " thing %d failed", thing); */

#define CNDB_LOGTX_INFO(_err, _cndb, _txid, _fmt, ...) \
    CNDB_LOG((_err), (_cndb), HSE_LOGPRI_INFO, "tx %lu" _fmt, (ulong)(_txid), ##__VA_ARGS__)

#define CNDB_LOGTX_ERR(_err, _cndb, _txid, _fmt, ...) \
    CNDB_LOG((_err), (_cndb), HSE_LOGPRI_ERR, "tx %lu" _fmt, (ulong)(_txid), ##__VA_ARGS__)

#if HSE_MOCKING
#include "cndb_internal_ut.h"
#endif /* HSE_MOCKING */
