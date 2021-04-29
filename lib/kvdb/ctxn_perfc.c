/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/hse_err.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/ctxn_perfc.h>

/* clang-format off */

/*
 * The NE() macro string-izes the enum.
 * perfc_ctrseti_alloc() parses this string to get the type(!).
 */

struct perfc_name ctxn_perfc_op[] = {
    NE(PERFC_BA_CTXNOP_ACTIVE,    1, "Count of active txns",       "c_ctxn_active"),
    NE(PERFC_RA_CTXNOP_ALLOC,     1, "Rate of ctxn allocs",        "r_ctxn_alloc(/s)"),
    NE(PERFC_RA_CTXNOP_BEGIN,     3, "Rate of ctxn begins",        "r_ctxn_begin(/s)"),
    NE(PERFC_RA_CTXNOP_COMMIT,    3, "Rate of ctxn commits",       "r_ctxn_commit(/s)"),
    NE(PERFC_LT_CTXNOP_COMMIT,    3, "Latency of ctxn commits",    "l_ctxn_commit(/s)"),
    NE(PERFC_RA_CTXNOP_ABORT,     3, "Rate of ctxn aborts",        "r_ctxn_abort(/s)"),
    NE(PERFC_RA_CTXNOP_LOCKFAIL,  2, "Rate of key lock failures",  "r_ctxn_lockfail(/s)"),
    NE(PERFC_RA_CTXNOP_FREE,      1, "Rate of ctxn frees",         "r_ctxn_free(/s)"),
};

NE_CHECK(ctxn_perfc_op, PERFC_EN_CTXNOP, "ctxn_perfc_op table/enum mismatch");

/* clang-format on */

void
ctxn_perfc_init(void)
{
    ctxn_perfc_op[PERFC_LT_CTXNOP_COMMIT].pcn_samplepct = 3;
}

void
ctxn_perfc_fini(void)
{
}
