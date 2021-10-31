/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/mclass_policy.h>

#include <mpool/mpool.h>

#include "cn_internal.h"
#include "cn_perfc_internal.h"

#define STATIC

struct perfc_name cn_perfc_get[] _dt_section = {
    NE(PERFC_RA_CNGET_GET, 2, "Count of cN gets", "c_get(/s)"),
    NE(PERFC_RA_CNGET_MISS, 2, "Count of cN misses", "c_mis(/s)"),

    NE(PERFC_DI_CNGET_DEPTH, 3, "cN levels examined", "d_lvl", 7),
    NE(PERFC_DI_CNGET_NKVSET, 3, "cN kvsets examined", "d_kvs", 7),

    NE(PERFC_LT_CNGET_GET, 3, "Latency of cN get", "l_get(ns)", 7),
    NE(PERFC_LT_CNGET_GET_L0, 3, "Latency of cN get in L0", "l_get_l0(ns)"),
    NE(PERFC_LT_CNGET_GET_L1, 3, "Latency of cN get in L1", "l_get_l1(ns)"),
    NE(PERFC_LT_CNGET_GET_L2, 3, "Latency of cN get in L2", "l_get_l2(ns)"),
    NE(PERFC_LT_CNGET_GET_L3, 3, "Latency of cN get in L3", "l_get_l3(ns)"),
    NE(PERFC_LT_CNGET_GET_L4, 3, "Latency of cN get in L4", "l_get_l4(ns)"),
    NE(PERFC_LT_CNGET_GET_L5, 3, "Latency of cN get in L5", "l_get_l5(ns)"),
    NE(PERFC_LT_CNGET_PROBEPFX, 3, "Latency of cN pfx probe", "l_pprobe(ns)"),
    NE(PERFC_LT_CNGET_MISS, 3, "Latency of cN misses", "l_mis(ns)"),
    NE(PERFC_RA_CNGET_TOMB, 3, "Count of cN tombs", "c_tmb(/s)")
};

struct perfc_name cn_perfc_compact[] _dt_section = {
    NE(PERFC_LT_CNCOMP_TOTAL, 2, "comp latency", "l_comp"),

    NE(PERFC_BA_CNCOMP_START, 3, "started", "started"),
    NE(PERFC_BA_CNCOMP_FINISH, 3, "finished", "finished"),
    NE(PERFC_RA_CNCOMP_RREQS, 3, "read requests", "rreqs"),
    NE(PERFC_RA_CNCOMP_RBYTES, 3, "read bytes", "rbytes"),
    NE(PERFC_RA_CNCOMP_WREQS, 3, "write requests", "wreqs"),
    NE(PERFC_RA_CNCOMP_WBYTES, 3, "write bytes", "wbytes"),
    NE(PERFC_DI_CNCOMP_VBUTIL, 3, "vblock util", "vb_util(%)"),
    NE(PERFC_DI_CNCOMP_VBDEAD, 3, "dead vblocks", "vb_dead(%)"),
    NE(PERFC_DI_CNCOMP_VBCNT, 3, "no. of vblocks", "vb_cnt"),
    NE(PERFC_DI_CNCOMP_VGET, 3, "vget time", "vb_gettime(ns)"),
};

struct perfc_name cn_perfc_shape[] _dt_section = {
    NE(PERFC_BA_CNSHAPE_NODES, 2, "nodes", "nodes"),
    NE(PERFC_BA_CNSHAPE_AVGLEN, 2, "avglen", "avglen"),
    NE(PERFC_BA_CNSHAPE_AVGSIZE, 2, "avgsize", "avgsize"),
    NE(PERFC_BA_CNSHAPE_MAXLEN, 2, "maxlen", "maxlen"),
    NE(PERFC_BA_CNSHAPE_MAXSIZE, 2, "maxsize", "maxsize"),
};

struct perfc_name cn_perfc_capped[] _dt_section = {
    NE(PERFC_BA_CNCAPPED_DEPTH, 2, "lag", "lag"),
    NE(PERFC_BA_CNCAPPED_ACTIVE, 3, "active iterators", "active"),
    NE(PERFC_BA_CNCAPPED_PTSEQ, 3, "seqno of ptombs", "ptseq"),
    NE(PERFC_BA_CNCAPPED_NEW, 3, "new kvsets", "new"),
    NE(PERFC_BA_CNCAPPED_OLD, 3, "old (valid) kvsets", "old"),
};

NE_CHECK(cn_perfc_capped, PERFC_EN_CNCAPPED, "cn_perfc_capped table/enum mismatch");

struct perfc_name cn_perfc_mclass[] _dt_section = {
    NE(PERFC_BA_CNMCLASS_ROOTK_STAGING, 3, "root_key_staging_alloc", "root_key_staging(b)"),
    NE(PERFC_BA_CNMCLASS_ROOTK_CAPACITY, 3, "root_key_capacity_alloc", "root_key_capacity(b)"),
    NE(PERFC_BA_CNMCLASS_ROOTV_STAGING, 3, "root_value_staging_alloc", "root_value_staging(b)"),
    NE(PERFC_BA_CNMCLASS_ROOTV_CAPACITY, 3, "root_value_capacity_alloc", "root_value_capacity(b)"),
    NE(PERFC_BA_CNMCLASS_INTK_STAGING, 3, "int_key_staging_alloc", "int_key_staging(b)"),
    NE(PERFC_BA_CNMCLASS_INTK_CAPACITY, 3, "int_key_capacity_alloc", "int_key_capacity(b)"),
    NE(PERFC_BA_CNMCLASS_INTV_STAGING, 3, "int_value_staging_alloc", "int_value_staging(b)"),
    NE(PERFC_BA_CNMCLASS_INTV_CAPACITY, 3, "int_value_capacity_alloc", "int_value_capacity(b)"),
    NE(PERFC_BA_CNMCLASS_LEAFK_STAGING, 3, "leaf_key_staging_alloc", "leaf_key_staging(b)"),
    NE(PERFC_BA_CNMCLASS_LEAFK_CAPACITY, 3, "leaf_key_capacity_alloc", "leaf_key_capacity(b)"),
    NE(PERFC_BA_CNMCLASS_LEAFV_STAGING, 3, "leaf_value_staging_alloc", "leaf_value_staging(b)"),
    NE(PERFC_BA_CNMCLASS_LEAFV_CAPACITY, 3, "leaf_value_capacity_alloc", "leaf_value_capacity(b)"),
};

NE_CHECK(cn_perfc_mclass, PERFC_EN_CNMCLASS, "cn_perfc_mclass table/enum mismatch");

static_assert(
    NELEM(cn_perfc_mclass) == HSE_MPOLICY_AGE_CNT * HSE_MPOLICY_DTYPE_CNT * HSE_MPOLICY_MEDIA_CNT,
    "cn_perfc_mclass entries mismatched");

uint
cn_perfc_mclass_get_idx(uint agegroup, uint dtype, uint mclass)
{
    return PERFC_BA_CNMCLASS_ROOTK_STAGING + agegroup * HSE_MPOLICY_AGE_CNT +
           dtype * HSE_MPOLICY_DTYPE_CNT + ((mclass == MP_MED_CAPACITY) ? 1 : 0);
}

NE_CHECK(cn_perfc_get, PERFC_EN_CNGET, "cn_perfc_get table/enum mismatch");

NE_CHECK(cn_perfc_compact, PERFC_EN_CNCOMP, "cn_perfc_compact table/enum mismatch");

NE_CHECK(cn_perfc_shape, PERFC_EN_CNSHAPE, "cn_perfc_shape table/enum mismatch");

STATIC
void
cn_perfc_bkts_create(struct perfc_name *pcn, int edgec, u64 *edgev, uint sample_pct)
{
    merr_t            err;
    struct perfc_ivl *ivl;

    err = perfc_ivl_create(edgec, edgev, &ivl);
    if (err) {
        log_errx("%s counters: perfc_ivl_create failed @@e", err, pcn->pcn_name);
        return;
    }

    pcn->pcn_samplepct = sample_pct;
    pcn->pcn_ivl = ivl;
}

STATIC
void
cn_perfc_bkts_destroy(struct perfc_name *pcn)
{
    if (pcn->pcn_ivl) {
        perfc_ivl_destroy(pcn->pcn_ivl);
        pcn->pcn_ivl = 0;
    }
}

void
cn_perfc_alloc(struct cn *cn, uint prio)
{
    char group[128];

    snprintf(group, sizeof(group), "kvdb/%s/kvs/%s", cn->cn_kvdb_alias, cn->cn_kvsname);

    /* Not considered fatal if perfc fails */
    perfc_alloc(cn_perfc_get, group, "cnget", prio, &cn->cn_pc_get);
    perfc_alloc(cn_perfc_compact, group, "ingest", prio, &cn->cn_pc_ingest);
    perfc_alloc(cn_perfc_compact, group, "spill", prio, &cn->cn_pc_spill);
    perfc_alloc(cn_perfc_compact, group, "kcompact", prio, &cn->cn_pc_kcompact);
    perfc_alloc(cn_perfc_compact, group, "kvcompact", prio, &cn->cn_pc_kvcompact);
    perfc_alloc(cn_perfc_shape, group, "rnode", prio, &cn->cn_pc_shape_rnode);
    perfc_alloc(cn_perfc_shape, group, "inode", prio, &cn->cn_pc_shape_inode);
    perfc_alloc(cn_perfc_shape, group, "lnode", prio, &cn->cn_pc_shape_lnode);
    perfc_alloc(cn_perfc_capped, group, "capped", prio, &cn->cn_pc_capped);
    perfc_alloc(cn_perfc_mclass, group, "mclass", prio, &cn->cn_pc_mclass);
}

void
cn_perfc_free(struct cn *cn)
{
    perfc_free(&cn->cn_pc_get);
    perfc_free(&cn->cn_pc_ingest);
    perfc_free(&cn->cn_pc_spill);
    perfc_free(&cn->cn_pc_kcompact);
    perfc_free(&cn->cn_pc_kvcompact);
    perfc_free(&cn->cn_pc_shape_rnode);
    perfc_free(&cn->cn_pc_shape_inode);
    perfc_free(&cn->cn_pc_shape_lnode);
    perfc_free(&cn->cn_pc_capped);
    perfc_free(&cn->cn_pc_mclass);
}

/* NOTE: called once per KVDB, not once per CN */
void
cn_perfc_init(void)
{
    uint sample_pct = 7;

    u64 cnget_depth_bkts[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

    u64 cnget_kvset_bkts[] = { 5, 10, 15, 20, 25, 30, 35, 40, 50, 60, 70, 80, 90, 100, 200, 300 };

    u64 cncmp_pct_bkts[] = { 10, 20, 30, 40, 50, 60, 70, 80, 90 };

    u64 cncmp_vblk_bkts[PERFC_IVL_MAX];
    int i;
    u64 cncmp_vget_bkts[PERFC_IVL_MAX];

    cn_perfc_bkts_create(
        &cn_perfc_get[PERFC_DI_CNGET_DEPTH], NELEM(cnget_depth_bkts), cnget_depth_bkts, sample_pct);

    cn_perfc_bkts_create(
        &cn_perfc_get[PERFC_DI_CNGET_NKVSET],
        NELEM(cnget_kvset_bkts),
        cnget_kvset_bkts,
        sample_pct);

    cn_perfc_bkts_create(
        &cn_perfc_compact[PERFC_DI_CNCOMP_VBUTIL],
        NELEM(cncmp_pct_bkts),
        cncmp_pct_bkts,
        sample_pct);

    cn_perfc_bkts_create(
        &cn_perfc_compact[PERFC_DI_CNCOMP_VBDEAD],
        NELEM(cncmp_pct_bkts),
        cncmp_pct_bkts,
        sample_pct);

    cncmp_vblk_bkts[0] = 1;
    for (i = 1; i < PERFC_IVL_MAX; i++)
        cncmp_vblk_bkts[i] = cncmp_vblk_bkts[i - 1] * 2;

    cn_perfc_bkts_create(
        &cn_perfc_compact[PERFC_DI_CNCOMP_VBCNT], PERFC_IVL_MAX, cncmp_vblk_bkts, sample_pct);

    cncmp_vget_bkts[0] = 1;
    for (i = 1; i < PERFC_IVL_MAX; i++)
        cncmp_vget_bkts[i] = cncmp_vget_bkts[i - 1] * 2;

    cn_perfc_bkts_create(
        &cn_perfc_compact[PERFC_DI_CNCOMP_VGET],
        NELEM(cncmp_vget_bkts),
        cncmp_vget_bkts,
        sample_pct);
}

void
cn_perfc_fini(void)
{
    cn_perfc_bkts_destroy(&cn_perfc_get[PERFC_DI_CNGET_DEPTH]);
    cn_perfc_bkts_destroy(&cn_perfc_get[PERFC_DI_CNGET_NKVSET]);
    cn_perfc_bkts_destroy(&cn_perfc_compact[PERFC_DI_CNCOMP_VBUTIL]);
    cn_perfc_bkts_destroy(&cn_perfc_compact[PERFC_DI_CNCOMP_VBDEAD]);
    cn_perfc_bkts_destroy(&cn_perfc_compact[PERFC_DI_CNCOMP_VBCNT]);
    cn_perfc_bkts_destroy(&cn_perfc_compact[PERFC_DI_CNCOMP_VGET]);
}
