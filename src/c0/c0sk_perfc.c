/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/hse_err.h>

#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/ikvdb.h>

#include "c0skm_internal.h"

/*
 * The NE() macro string-izes the enum.
 * perfc_ctrseti_alloc() parses this string to get the type(!).
 */

struct perfc_name c0sk_perfc_op[] = {
    NE(PERFC_LT_C0SKOP_GET, 3, "Latency of c0sk gets", "l_get(/s)", 7),
    NE(PERFC_RA_C0SKOP_GET, 3, "Count of c0sk gets", "c_get(/s)"),
    NE(PERFC_RA_C0SKOP_PUT, 3, "Count of c0sk puts", "c_put(/s)"),
    NE(PERFC_LT_C0SKOP_PUT, 3, "Latency of c0sk puts", "l_put(/s)"),
    NE(PERFC_RA_C0SKOP_DEL, 3, "Count of c0sk dels", "c_del(/s)"),
    NE(PERFC_LT_C0SKOP_DEL, 3, "Latency of c0sk dels", "l_del(/s)"),
};

struct perfc_name c0sk_perfc_ingest[] = {
    NE(PERFC_BA_C0SKING_QLEN, 2, "Ingest queue length", "d_queue_len"),
    NE(PERFC_DI_C0SKING_PREP, 2, "Ingest prep. time", "l_ingprep(ms)"),
    NE(PERFC_DI_C0SKING_FIN, 2, "Ingest finish time", "l_ingfin(ms)"),
    NE(PERFC_DI_C0SKING_KVMSDSIZE, 2, "kvms size", "c_kvmsdsz(mb)"),

    NE(PERFC_BA_C0SKING_WIDTH, 3, "Ingest width", "d_width"),
    NE(PERFC_DI_C0SKING_THRSR, 3, "Throttle sensor", "c_thrsr", 10),
    NE(PERFC_DI_C0SKING_MEM, 3, "Ingest memory limit", "c_ingmem"),
};

NE_CHECK(c0sk_perfc_op, PERFC_EN_C0SKOP, "c0sk_perfc_op table/enum mismatch");

NE_CHECK(c0sk_perfc_ingest, PERFC_EN_C0SKING, "c0sk_perfc_ingest table/enum mismatch");

void
c0sk_perfc_init(void)
{
    struct perfc_ivl *ivl;

    int    i;
    u64    boundv[PERFC_IVL_MAX];
    merr_t err;

    /* Allocate interval instance for the distribution counters (pow2). */
    boundv[0] = 1;
    for (i = 1; i < PERFC_IVL_MAX; i++)
        boundv[i] = boundv[i - 1] * 2;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &ivl);
    if (err) {
        hse_elog(HSE_WARNING "c0skm perfc, unable to allocate pow2 ivl: @@e", err);
        return;
    }

    c0sk_perfc_ingest[PERFC_DI_C0SKING_PREP].pcn_ivl = ivl;
    c0sk_perfc_ingest[PERFC_DI_C0SKING_FIN].pcn_ivl = ivl;
    c0sk_perfc_ingest[PERFC_DI_C0SKING_THRSR].pcn_ivl = ivl;
    c0sk_perfc_ingest[PERFC_DI_C0SKING_MEM].pcn_ivl = ivl;
    c0sk_perfc_ingest[PERFC_DI_C0SKING_KVMSDSIZE].pcn_ivl = ivl;

    c0sk_perfc_op[PERFC_LT_C0SKOP_GET].pcn_samplepct = 3;
    c0sk_perfc_op[PERFC_LT_C0SKOP_PUT].pcn_samplepct = 3;
    c0sk_perfc_op[PERFC_LT_C0SKOP_DEL].pcn_samplepct = 3;
}

void
c0sk_perfc_fini(void)
{
    const struct perfc_ivl *ivl;

    ivl = c0sk_perfc_ingest[PERFC_DI_C0SKING_PREP].pcn_ivl;
    if (ivl) {
        c0sk_perfc_ingest[PERFC_DI_C0SKING_PREP].pcn_ivl = 0;
        perfc_ivl_destroy(ivl);
    }
}

/* c0skm related perfc initialization */

struct perfc_name c0skm_perfc_op[] = {
    NE(PERFC_LT_C0SKM_INGEST, 2, "Latency of c0skm ingest", "l_cskmi(ns)"),

    NE(PERFC_RA_C0SKM_SYNC, 3, "Rate of c0skm sync", "c_sync(/s)"),
    NE(PERFC_LT_C0SKM_SYNC, 3, "Latency of c0skm sync", "l_sync(ns)"),
    NE(PERFC_RA_C0SKM_FLUSH, 3, "Rate of c0skm flush", "c_flush(/s)"),
    NE(PERFC_LT_C0SKM_FLUSH, 3, "Latency of c0skm flush", "l_flush(ns)"),
    NE(PERFC_RA_C0SKM_TSYNCI, 3, "Count of c0skm tsyncs", "c_tsyn(/s)"),
    NE(PERFC_RA_C0SKM_TSYNCS, 3, "Count of c0skm tsyncs skip", "c_tsyns(/s)"),
    NE(PERFC_DI_C0SKM_TSYNCD, 3, "Expiry of first request", "d_expry(ns)", 10),
    NE(PERFC_RA_C0SKM_TSYNCE, 3, "Tsyncs enqueued", "l_expry(ns)"),
    NE(PERFC_RA_C0SKM_KVMSP, 3, "Rate of c0skm kvms proc.", "c_kvmsp(/s)"),
    NE(PERFC_BA_C0SKM_KVMSS, 3, "Count of c0skm kvms skipped", "c_kvmss"),
    NE(PERFC_BA_C0SKM_KVMSF, 3, "Count of c0skm kvms final", "c_kvmsf"),
    NE(PERFC_LT_C0SKM_KVMSI, 3, "Latency of c0skm kvms ing.", "l_kvmsi(ns)"),
    NE(PERFC_DI_C0SKM_VBLDRT, 3, "Ratio of values from c0/c1", "d_vbldrt(b)"),
};

NE_CHECK(c0skm_perfc_op, PERFC_EN_C0SKMOP, "c0skm perfc ops table/enum mismatch");

struct perfc_name c0skm_perfc_kv[] = {
    NE(PERFC_LT_C0SKM_C1ING, 2, "Latency of c0skm c1 ingests", "l_c1ing(ns)"),

    NE(PERFC_RA_C0SKM_ITERC, 3, "Rate of c0kvmsm iter create", "c_itc(/s)"),
    NE(PERFC_RA_C0SKM_ITERD, 3, "Rate of c0kvmsm iter destroy", "c_itd(/s)"),
    NE(PERFC_RA_C0SKM_C1ING, 3, "Rate of c0skm c1 ingests", "c_c1ing(/s)"),
    NE(PERFC_DI_C0SKM_KVBPI, 3, "Count of kvb per iter", "d_kvbn"),
    NE(PERFC_DI_C0SKM_KVBSZ, 3, "Size of kvb", "d_kvbs(b)"),
    NE(PERFC_DI_C0SKM_KVKPB, 3, "Count of keys per kvb", "d_kvbkc"),
    NE(PERFC_DI_C0SKM_KVVPB, 3, "Count of vals per kvb", "d_kvbvc"),
    NE(PERFC_DI_C0SKM_KVKSK, 3, "Count of keys skipped", "d_kvbks"),
    NE(PERFC_BA_C0SKM_KVKPN, 3, "Count of tx keys pending", "d_kpend"),
    NE(PERFC_BA_C0SKM_KVVPN, 3, "Count of tx vals pending", "d_vpend"),
    NE(PERFC_LT_C0SKM_COPY, 3, "Latency of c0skm copy", "l_copy(ns)"),
    NE(PERFC_DI_C0SKM_DTIME, 3, "c0skm dtime", "d_dtime(ms)", 10),
    NE(PERFC_DI_C0SKM_DSIZE, 3, "c0skm dsize", "d_dsize(b)", 10),
};

NE_CHECK(c0skm_perfc_kv, PERFC_EN_C0SKMKV, "c0skm perfc kv table/enum mismatch");

#define PERFC_HUNDRED_IVL 9

_Static_assert(
    PERFC_HUNDRED_IVL <= PERFC_IVL_MAX,
    "c0skm perfc hundred interval greater than max interval");

void
c0skm_perfc_init(void)
{
    struct perfc_ivl *ivl;

    int    i;
    u64    boundv[PERFC_IVL_MAX];
    merr_t err;

    /* Allocate interval instance for the distribution counters (pow2). */
    for (i = 0; i < PERFC_IVL_MAX; i++)
        boundv[i] = (i > 0) ? (boundv[i - 1] * 2) : 1;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &ivl);
    if (err) {
        hse_elog(HSE_WARNING "c0skm perfc, unable to allocate pow2 ivl: @@e", err);
        return;
    }

    c0skm_perfc_kv[PERFC_DI_C0SKM_KVBPI].pcn_ivl = ivl;
    c0skm_perfc_kv[PERFC_DI_C0SKM_KVBSZ].pcn_ivl = ivl;
    c0skm_perfc_kv[PERFC_DI_C0SKM_KVKPB].pcn_ivl = ivl;
    c0skm_perfc_kv[PERFC_DI_C0SKM_KVVPB].pcn_ivl = ivl;
    c0skm_perfc_kv[PERFC_DI_C0SKM_KVKSK].pcn_ivl = ivl;
    c0skm_perfc_op[PERFC_DI_C0SKM_TSYNCD].pcn_ivl = ivl;
    c0skm_perfc_kv[PERFC_DI_C0SKM_DSIZE].pcn_ivl = ivl;
    c0skm_perfc_kv[PERFC_DI_C0SKM_DTIME].pcn_ivl = ivl;

    /* Allocate interval instance for the distribution counters(pct). */
    for (i = 0; i < PERFC_HUNDRED_IVL; i++)
        boundv[i] = (i + 1) * 10;

    err = perfc_ivl_create(PERFC_HUNDRED_IVL, boundv, &ivl);
    if (err) {
        hse_elog(HSE_WARNING "c0skm perfc, unable to allocate pct ivl: @@e", err);
        return;
    }

    c0skm_perfc_op[PERFC_DI_C0SKM_VBLDRT].pcn_ivl = ivl;
}

void
c0skm_perfc_fini(void)
{
    const struct perfc_ivl *ivl;

    ivl = c0skm_perfc_kv[PERFC_DI_C0SKM_KVBPI].pcn_ivl;
    if (ivl) {
        c0skm_perfc_kv[PERFC_DI_C0SKM_KVBPI].pcn_ivl = 0;
        perfc_ivl_destroy(ivl);
    }

    ivl = c0skm_perfc_op[PERFC_DI_C0SKM_VBLDRT].pcn_ivl;
    if (ivl) {
        c0skm_perfc_op[PERFC_DI_C0SKM_VBLDRT].pcn_ivl = 0;
        perfc_ivl_destroy(ivl);
    }
}

void
c0skm_perfc_alloc(struct c0sk_mutation *c0skm, const char *mpname)
{
    int i;

    struct {
        struct perfc_name *cdesc;
        uint               nctrs;
        char *             cset_name;
        struct perfc_set * cset;
        char *             errmsg;
    } c0skm_pcsets[] = {
        { c0skm_perfc_op,
          PERFC_EN_C0SKMOP,
          "c0skmop",
          &c0skm->c0skm_pcset_op,
          "c0skm op perf counter alloc failed" },
        { c0skm_perfc_kv,
          PERFC_EN_C0SKMKV,
          "c0skmkv",
          &c0skm->c0skm_pcset_kv,
          "c0skm kv perf counter alloc failed" },
    };

    if (ev(!c0skm || !mpname))
        return;

    /* Allocate the perf counter set */
    for (i = 0; i < NELEM(c0skm_pcsets); i++) {

        if (!c0skm_pcsets[i].cset)
            continue;

        if (perfc_ctrseti_alloc(
                COMPNAME,
                mpname,
                c0skm_pcsets[i].cdesc,
                c0skm_pcsets[i].nctrs,
                c0skm_pcsets[i].cset_name,
                c0skm_pcsets[i].cset))
            hse_log(HSE_WARNING "%s", c0skm_pcsets[i].errmsg);
    }
}

void
c0skm_perfc_free(struct c0sk_mutation *c0skm)
{
    perfc_ctrseti_free(&c0skm->c0skm_pcset_op);
    perfc_ctrseti_free(&c0skm->c0skm_pcset_kv);
}
