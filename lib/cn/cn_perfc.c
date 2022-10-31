/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/platform.h>
#include <hse/logging/logging.h>

#include <hse/ikvdb/tuple.h>
#include <hse/ikvdb/mclass_policy.h>

#include <hse/mpool/mpool.h>

#include "cn_internal.h"
#include "cn_perfc_internal.h"

/* clang-format off */

struct perfc_name cn_perfc_get[] _dt_section = {
    NE(PERFC_RA_CNGET_MISS,      2, "cN lookup miss rate",           "c_mis(/s)"),
    NE(PERFC_RA_CNGET_GET,       2, "cN lookup hit rate",            "c_get(/s)"),
    NE(PERFC_RA_CNGET_TOMB,      2, "cN lookup tomb hit rate",       "c_tmb(/s)"),
    NE(PERFC_RA_CNGET_PTOMB,     2, "cN lookup ptomb hit rate",      "r_cnget_ptmb(/s)"),
    NE(PERFC_RA_CNGET_MULTIPLE,  2, "cN lookup multiple hit rate",   "r_cnget_multiple(/s)"),

    /* ROOT must be active for LEAF to record.
     */
    NE(PERFC_LT_CNGET_GET_ROOT,  3, "cN root hit latency",           "l_get_r(ns)", 13),
    NE(PERFC_LT_CNGET_GET_LEAF,  3, "cN leaf hit latency",           "l_get_l(ns)", 17),

    /* LT_CNGET_GET must be active for MISS and/or PROBE_PFX to record.
     */
    NE(PERFC_LT_CNGET_GET,       3, "cN avg hit latency",            "l_get(ns)", 7),
    NE(PERFC_LT_CNGET_MISS,      3, "cN avg miss latency",           "l_mis(ns)", 7),
    NE(PERFC_LT_CNGET_PROBE_PFX, 3, "Latency of cN pfx probe",       "l_pprobe(ns)", 7),
};

struct perfc_name cn_perfc_compact[] _dt_section = {
    NE(PERFC_LT_CNCOMP_TOTAL,    2, "cN comp latency",               "l_comp"),

    NE(PERFC_BA_CNCOMP_START,    3, "cN comp starts",                "started"),
    NE(PERFC_BA_CNCOMP_FINISH,   3, "cN comp finishes",              "finished"),
    NE(PERFC_RA_CNCOMP_RREQS,    3, "cN comp read requests",         "rreqs"),
    NE(PERFC_RA_CNCOMP_RBYTES,   3, "cN comp read bytes",            "rbytes"),
    NE(PERFC_RA_CNCOMP_WREQS,    3, "cN comp write requests",        "wreqs"),
    NE(PERFC_RA_CNCOMP_WBYTES,   3, "cN comp write bytes",           "wbytes"),
    NE(PERFC_DI_CNCOMP_VGET,     3, "cN comp vget time",             "vb_gettime(ns)"),
};

struct perfc_name cn_perfc_shape[] _dt_section = {
    NE(PERFC_BA_CNSHAPE_NODES,   2, "cN shape nodes",                "nodes"),
    NE(PERFC_BA_CNSHAPE_AVGLEN,  2, "cN shape avglen",               "avglen"),
    NE(PERFC_BA_CNSHAPE_AVGSIZE, 2, "cN shape avgsize",              "avgsize"),
    NE(PERFC_BA_CNSHAPE_MAXLEN,  2, "cN shape maxlen",               "maxlen"),
    NE(PERFC_BA_CNSHAPE_MAXSIZE, 2, "cN shape maxsize",              "maxsize"),
};

struct perfc_name cn_perfc_capped[] _dt_section = {
    NE(PERFC_BA_CNCAPPED_DEPTH,  2, "cN capped lag",                 "c_cncap_lag"),
    NE(PERFC_BA_CNCAPPED_ACTIVE, 3, "cN capped active iterators",    "c_cncap_active"),
    NE(PERFC_BA_CNCAPPED_PTSEQ,  3, "cN capped seqno of ptombs",     "c_cncap_ptseq"),
    NE(PERFC_BA_CNCAPPED_NEW,    3, "cN capped new kvsets",          "c_cncap_new"),
    NE(PERFC_BA_CNCAPPED_OLD,    3, "cN capped old (valid) kvsets",  "c_cncap_old"),
};

NE_CHECK(cn_perfc_get, PERFC_EN_CNGET, "cn_perfc_get table/enum mismatch");
NE_CHECK(cn_perfc_compact, PERFC_EN_CNCOMP, "cn_perfc_compact table/enum mismatch");
NE_CHECK(cn_perfc_shape, PERFC_EN_CNSHAPE, "cn_perfc_shape table/enum mismatch");
NE_CHECK(cn_perfc_capped, PERFC_EN_CNCAPPED, "cn_perfc_capped table/enum mismatch");

static_assert(PERFC_RA_CNGET_MISS == 1 && NOT_FOUND == 1,
              "PERFC_RA_CNGET_MISS out of sync with enum key_lookup_res");
static_assert(PERFC_RA_CNGET_GET == 2 && FOUND_VAL == 2,
              "PERFC_RA_CNGET_GET out of sync with enum key_lookup_res");
static_assert(PERFC_RA_CNGET_TOMB == 3 && FOUND_TMB == 3,
              "PERFC_RA_CNGET_TOMB out of sync with enum key_lookup_res");
static_assert(PERFC_RA_CNGET_PTOMB == 4 && FOUND_PTMB == 4,
              "PERFC_RA_CNGET_PTOMB out of sync with enum key_lookup_res");
static_assert(PERFC_RA_CNGET_MULTIPLE == 5 && FOUND_MULTIPLE == 5,
              "PERFC_RA_CNGET_FMULT out of sync with enum key_lookup_res");

/* clang-format on */

void
cn_perfc_bkts_create(struct perfc_name *pcn, int edgec, u64 *edgev, uint sample_pct)
{
    merr_t            err;
    struct perfc_ivl *ivl;

    err = perfc_ivl_create(edgec, edgev, &ivl);
    if (err) {
        log_errx("%s counters: perfc_ivl_create failed", err, pcn->pcn_name);
        return;
    }

    pcn->pcn_samplepct = sample_pct;
    pcn->pcn_ivl = ivl;
}

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

    snprintf(group, sizeof(group), "kvdbs/%s/kvs/%s", cn->cn_kvdb_alias, cn->cn_kvs_name);

    /* Not considered fatal if perfc fails */
    perfc_alloc(cn_perfc_get, group, "cnget", prio, &cn->cn_pc_get);
    perfc_alloc(cn_perfc_compact, group, "ingest", prio, &cn->cn_pc_ingest);
    perfc_alloc(cn_perfc_compact, group, "spill", prio, &cn->cn_pc_spill);
    perfc_alloc(cn_perfc_compact, group, "split", prio, &cn->cn_pc_split);
    perfc_alloc(cn_perfc_compact, group, "join", prio, &cn->cn_pc_join);
    perfc_alloc(cn_perfc_compact, group, "kcompact", prio, &cn->cn_pc_kcompact);
    perfc_alloc(cn_perfc_compact, group, "kvcompact", prio, &cn->cn_pc_kvcompact);
    perfc_alloc(cn_perfc_shape, group, "rnode", prio, &cn->cn_pc_shape_rnode);
    perfc_alloc(cn_perfc_shape, group, "lnode", prio, &cn->cn_pc_shape_lnode);
    perfc_alloc(cn_perfc_capped, group, "capped", prio, &cn->cn_pc_capped);
}

void
cn_perfc_free(struct cn *cn)
{
    perfc_free(&cn->cn_pc_get);
    perfc_free(&cn->cn_pc_ingest);
    perfc_free(&cn->cn_pc_spill);
    perfc_free(&cn->cn_pc_split);
    perfc_free(&cn->cn_pc_join);
    perfc_free(&cn->cn_pc_kcompact);
    perfc_free(&cn->cn_pc_kvcompact);
    perfc_free(&cn->cn_pc_shape_rnode);
    perfc_free(&cn->cn_pc_shape_lnode);
    perfc_free(&cn->cn_pc_capped);
}

/* NOTE: called once per KVDB, not once per CN */
void
cn_perfc_init(void)
{
    u64 cncmp_vget_bkts[PERFC_IVL_MAX];
    uint sample_pct = 7;

    cncmp_vget_bkts[0] = 1;
    for (int i = 1; i < PERFC_IVL_MAX; i++)
        cncmp_vget_bkts[i] = cncmp_vget_bkts[i - 1] * 2;

    cn_perfc_bkts_create(&cn_perfc_compact[PERFC_DI_CNCOMP_VGET], NELEM(cncmp_vget_bkts),
                         cncmp_vget_bkts, sample_pct);
}

void
cn_perfc_fini(void)
{
    cn_perfc_bkts_destroy(&cn_perfc_compact[PERFC_DI_CNCOMP_VGET]);
}
