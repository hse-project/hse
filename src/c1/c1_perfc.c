/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/string.h>

#include "c1_private.h"

struct perfc_name c1_perfc_op[] = {
    NE(PERFC_RA_C1_SYNC, 3, "Rate of c1 sync", "c_sync(/s)"),
    NE(PERFC_LT_C1_SYNC, 3, "Latency of c1 sync", "l_sync(ns)"),
    NE(PERFC_RA_C1_FLUSH, 3, "Rate of c1 flush", "c_flsh(/s)"),
    NE(PERFC_LT_C1_FLUSH, 3, "Latency of c1 flush", "l_flsh(ns)", 10),
    NE(PERFC_RA_C1_TXBEG, 3, "Rate of c1 txn begin", "c_txbg(/s)"),
    NE(PERFC_RA_C1_TXCOM, 3, "Rate of c1 txn commit", "c_txcm(/s)"),
    NE(PERFC_RA_C1_TXABT, 3, "Rate of c1 txn abort", "c_txab(/s)"),
};

NE_CHECK(c1_perfc_op, PERFC_EN_C1OP, "c1 perfc ops table/enum mismatch");

struct perfc_name c1_perfc_jrnl[] = {
    NE(PERFC_BA_C1_JRNL, 3, "Count of c1 journal IOs", "c_jnlio"),
    NE(PERFC_LT_C1_JRNL, 3, "Latency of c1 journal IOs", "l_jnlio(ns)"),
    NE(PERFC_BA_C1_JRNLC, 3, "Count of c1 journal compacts", "c_jnlc"),
    NE(PERFC_LT_C1_JRNLC, 3, "Latency of c1 jrnl compacts", "l_jnlc(ns)", 10),
};
NE_CHECK(c1_perfc_jrnl, PERFC_EN_C1JRNL, "c1 perfc journal table/enum mismatch");

struct perfc_name c1_perfc_kv[] = {
    NE(PERFC_BA_C1_KVBN, 3, "Count of c1 non-tx kvbs", "c_kvb"),
    NE(PERFC_BA_C1_KVBTX, 3, "Count of c1 tx kvbs", "c_txkvb"),
    NE(PERFC_BA_C1_KEYR, 3, "Count of c1 keys replayed", "c_krepl"),
    NE(PERFC_BA_C1_VALR, 3, "Count of c1 vals replayed", "c_vrepl"),
    NE(PERFC_BA_C1_PUTR, 3, "Count of c1 PUT replayed", "c_prepl"),
    NE(PERFC_BA_C1_DELR, 3, "Count of c1 DEL replayed", "c_drepl"),
};

NE_CHECK(c1_perfc_kv, PERFC_EN_C1KV, "c1 perfc kv table/enum mismatch");

struct perfc_name c1_perfc_io[] = {
    NE(PERFC_LT_C1_IOTOT, 2, "c1 io total time", "l_iot(ns)"),

    NE(PERFC_RA_C1_IOQUE, 3, "Rate of c1 io queued", "c_ioq(/s)"),
    NE(PERFC_RA_C1_IOPRO, 3, "Rate of c1 io processed", "c_iop(/s)"),
    NE(PERFC_LT_C1_IOQUE, 3, "c1 io wait time", "l_ioq(ns)"),
    NE(PERFC_LT_C1_IOQLK, 3, "c1 io q lock wait time", "l_iql(ns)", 10),
    NE(PERFC_LT_C1_IOSLK, 3, "c1 space lock wait time", "l_isl(ns)", 10),
    NE(PERFC_LT_C1_IOPRO, 3, "c1 io processing time", "l_iop(ns)"),
    NE(PERFC_BA_C1_IOERR, 3, "Count of c1 io errors", "c_ioerr"),
    NE(PERFC_BA_C1_IOMBK, 3, "Count of c1 mblk ios", "c_iombk"),
    NE(PERFC_BA_C1_IOMLG, 3, "Count of c1 mlog ios", "c_iombc"),
    NE(PERFC_DI_C1_IOMBK, 3, "Latency of c1 mblk ios", "l_mbk(ns)"),
    NE(PERFC_DI_C1_IOMLG, 3, "Latency of c1 mlog ios", "l_mlg(ns)", 10),
    NE(PERFC_LT_C1_MLGFL, 3, "Lat. of c1 mlog flushes", "l_mlf(ns)"),
    NE(PERFC_LT_C1_MB1FL, 3, "mblk interim flush lat.", "l_mb1(ns)", 10),
    NE(PERFC_LT_C1_MB2FL, 3, "mblk final flush lat.", "l_mb2(ns)", 10),
    NE(PERFC_DI_C1_IOVSZ, 3, "value size in pipeline", "c_valsz"),
    NE(PERFC_DI_C1_TREE, 3, "Latency of tree alloc", "l_tree(ns)"),
};

NE_CHECK(c1_perfc_io, PERFC_EN_C1IO, "c1 perfc io table/enum mismatch");

struct perfc_name c1_perfc_tree[] = {
    NE(PERFC_BA_C1_TALLOC, 3, "Count of c1 trees allocated", "c_tralo"),
    NE(PERFC_BA_C1_TACTIVE, 3, "Count of c1 trees active", "c_tract"),
    NE(PERFC_BA_C1_TREUSE, 3, "Count of c1 trees reused", "c_trreu"),
    NE(PERFC_BA_C1_TINVAL, 3, "Count of c1 trees invalidated", "c_trinv"),
    NE(PERFC_BA_C1_TREPL, 3, "Count of c1 trees replayed", "c_trrep"),
    NE(PERFC_BA_C1_TFLUSH, 3, "Count of c1 trees flushed", "c_trflu"),
};

NE_CHECK(c1_perfc_tree, PERFC_EN_C1TREE, "c1 perfc tree table/enum mismatch");

void
c1_perfc_init(void)
{
    struct perfc_ivl *ivl;

    merr_t err;
    int    i;
    u64    boundv[PERFC_IVL_MAX];

    /* Allocate interval instance for the distribution counters (pow2). */
    boundv[0] = 1;
    for (i = 1; i < PERFC_IVL_MAX; i++)
        boundv[i] = boundv[i - 1] * 2;

    err = perfc_ivl_create(PERFC_IVL_MAX, boundv, &ivl);
    if (err) {
        hse_elog(HSE_WARNING "c1 perfc, unable to allocate pow2 ivl: @@e", err);
        return;
    }

    c1_perfc_io[PERFC_DI_C1_IOMLG].pcn_ivl = ivl;
    c1_perfc_io[PERFC_DI_C1_IOMBK].pcn_ivl = ivl;
    c1_perfc_io[PERFC_DI_C1_IOVSZ].pcn_ivl = ivl;
    c1_perfc_io[PERFC_DI_C1_TREE].pcn_ivl = ivl;
}

void
c1_perfc_fini(void)
{
    const struct perfc_ivl *ivl;

    ivl = c1_perfc_io[PERFC_DI_C1_IOMLG].pcn_ivl;
    if (ivl) {
        c1_perfc_io[PERFC_DI_C1_IOMLG].pcn_ivl = NULL;
        c1_perfc_io[PERFC_DI_C1_IOMBK].pcn_ivl = NULL;
        c1_perfc_io[PERFC_DI_C1_IOVSZ].pcn_ivl = NULL;
        c1_perfc_io[PERFC_DI_C1_TREE].pcn_ivl = NULL;
        perfc_ivl_destroy(ivl);
    }
}

static merr_t
c1_perfc_name_init(const char *mpname, char *name, size_t len)
{
    if (ev(strlcpy(name, mpname, len) >= len)) {
        hse_log(HSE_WARNING "c1 perfc buffer too small");
        return merr(EINVAL);
    }

    return 0;
}

void
c1_perfc_alloc(struct c1 *c1, const char *mpname)
{
    char   name_buf[DT_PATH_COMP_ELEMENT_LEN];
    int    i;
    merr_t err;

    struct {
        struct perfc_name *cdesc;
        uint               nctrs;
        char *             cset_name;
        struct perfc_set * cset;
        char *             errmsg;
    } c1_pcsets[] = {
        { c1_perfc_op,
          PERFC_EN_C1OP,
          "c1op",
          &c1->c1_pcset_op,
          "c1 ops perf counter alloc failed" },
        { c1_perfc_kv, PERFC_EN_C1KV, "c1kv", &c1->c1_pcset_kv, "c1 kv perf counter alloc failed" },
        { c1_perfc_tree,
          PERFC_EN_C1TREE,
          "c1tree",
          &c1->c1_pcset_tree,
          "c1 tree perf counter alloc failed" },
    };

    if (ev(!c1 || !mpname))
        return;

    err = c1_perfc_name_init(mpname, name_buf, sizeof(name_buf));
    if (ev(err))
        return;

    for (i = 0; i < NELEM(c1_pcsets); i++) {

        if (!c1_pcsets[i].cset)
            continue;

        if (perfc_ctrseti_alloc(
                COMPNAME,
                name_buf,
                c1_pcsets[i].cdesc,
                c1_pcsets[i].nctrs,
                c1_pcsets[i].cset_name,
                c1_pcsets[i].cset))
            hse_log(HSE_ERR "%s", c1_pcsets[i].errmsg);
    }
}

void
c1_perfc_free(struct c1 *c1)
{
    perfc_ctrseti_free(&c1->c1_pcset_op);
    perfc_ctrseti_free(&c1->c1_pcset_kv);
    perfc_ctrseti_free(&c1->c1_pcset_tree);
}

void
c1_perfc_journal_alloc(struct perfc_set *cset, const char *mpname)
{
    char   name_buf[DT_PATH_COMP_ELEMENT_LEN];
    merr_t err;

    if (ev(!cset || !mpname))
        return;

    err = c1_perfc_name_init(mpname, name_buf, sizeof(name_buf));
    if (ev(err))
        return;

    if (perfc_ctrseti_alloc(COMPNAME, name_buf, c1_perfc_jrnl, PERFC_EN_C1JRNL, "c1jrnl", cset))
        hse_log(HSE_ERR "c1 journal perf counter alloc failed");
}

void
c1_perfc_journal_free(struct perfc_set *pcset)
{
    perfc_ctrseti_free(pcset);
}

void
c1_perfc_io_alloc(struct perfc_set *cset, const char *mpname)
{
    char   name_buf[DT_PATH_COMP_ELEMENT_LEN];
    merr_t err;

    if (ev(!cset || !mpname))
        return;

    err = c1_perfc_name_init(mpname, name_buf, sizeof(name_buf));
    if (ev(err))
        return;

    if (perfc_ctrseti_alloc(COMPNAME, name_buf, c1_perfc_io, PERFC_EN_C1IO, "c1io", cset))
        hse_log(HSE_ERR "c1 io perf counter alloc failed");
}

void
c1_perfc_io_free(struct perfc_set *pcset)
{
    perfc_ctrseti_free(pcset);
}
