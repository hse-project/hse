/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/perfc.h>

#include <hse_ikvdb/c0sk_perfc.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/ikvdb.h>

#include "c0sk_internal.h"

/* clang-format off */

struct perfc_name c0sk_perfc_op[] _dt_section = {
    NE(PERFC_LT_C0SKOP_GET, 3, "Latency of c0sk gets", "l_get(/s)", 7),
    NE(PERFC_RA_C0SKOP_GET, 3, "Count of c0sk gets",   "c_get(/s)"),
    NE(PERFC_RA_C0SKOP_PUT, 3, "Count of c0sk puts",   "c_put(/s)"),
    NE(PERFC_LT_C0SKOP_PUT, 3, "Latency of c0sk puts", "l_put(/s)", 7),
    NE(PERFC_RA_C0SKOP_DEL, 3, "Count of c0sk dels",   "c_del(/s)"),
    NE(PERFC_LT_C0SKOP_DEL, 3, "Latency of c0sk dels", "l_del(/s)", 7),
};

struct perfc_name c0sk_perfc_ingest[] _dt_section = {
    NE(PERFC_BA_C0SKING_QLEN,  2, "Ingest queue length", "c_ing_qlen"),
    NE(PERFC_DI_C0SKING_PREP,  2, "Ingest prep time",    "d_ing_prep(ms)"),
    NE(PERFC_DI_C0SKING_FIN,   2, "Ingest finish time",  "d_ing_finish(ms)"),
    NE(PERFC_BA_C0SKING_WIDTH, 3, "Ingest width",        "c_width"),
};

NE_CHECK(c0sk_perfc_op,     PERFC_EN_C0SKOP,  "c0sk_perfc_op table/enum mismatch");
NE_CHECK(c0sk_perfc_ingest, PERFC_EN_C0SKING, "c0sk_perfc_ingest table/enum mismatch");

/* clang-format on */

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
        log_errx("unable to allocate pow2 ivl: @@e", err);
        return;
    }

    c0sk_perfc_ingest[PERFC_DI_C0SKING_PREP].pcn_ivl = ivl;
    c0sk_perfc_ingest[PERFC_DI_C0SKING_FIN].pcn_ivl = ivl;
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

void
c0sk_perfc_alloc(struct c0sk_impl *self)
{
    struct kvdb_rparams *rp = self->c0sk_kvdb_rp;
    char group[128];

    snprintf(group, sizeof(group), "kvdb/%s", self->c0sk_kvdb_alias);

    perfc_alloc(c0sk_perfc_op, group, "set", rp->perfc_level, &self->c0sk_pc_op);
    perfc_alloc(c0sk_perfc_ingest, group, "set", rp->perfc_level, &self->c0sk_pc_ingest);
}

void
c0sk_perfc_free(struct c0sk_impl *self)
{
    perfc_free(&self->c0sk_pc_op);
    perfc_free(&self->c0sk_pc_ingest);
}
