/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/hse_err.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>

#include <hse_ikvdb/ctxn_perfc.h>

/*
 * The NE() macro string-izes the enum.
 * perfc_ctrseti_alloc() parses this string to get the type(!).
 */

struct perfc_name ctxn_perfc_op[] = {
    NE(PERFC_BA_CTXNOP_ACTIVE, 1, "Count of active txns", "c_active"),
    NE(PERFC_RA_CTXNOP_ALLOC, 1, "Count of ctxn allocs", "c_alloc(/s)"),
    NE(PERFC_RA_CTXNOP_FREE, 1, "Count of ctxn frees", "c_free(/s)"),

    NE(PERFC_RA_CTXNOP_BEGIN, 3, "Count of ctxn begins", "c_beg(/s)"),
    NE(PERFC_RA_CTXNOP_COMMIT, 3, "Count of ctxn commits", "c_cmt(/s)"),
    NE(PERFC_LT_CTXNOP_COMMIT, 3, "Latency of ctxn commits", "l_cmt(/s)"),
    NE(PERFC_RA_CTXNOP_ABORT, 3, "Count of ctxn aborts", "c_abt(/s)"),
    NE(PERFC_RA_CTXNOP_LOCK_DONE, 3, "Count of lock acquire success", "c_lksuc(/s)"),
    NE(PERFC_RA_CTXNOP_LOCK_FAILED, 3, "Count of lock acquire failure", "c_lkfld(/s)"),
};

NE_CHECK(ctxn_perfc_op, PERFC_EN_CTXNOP, "ctxn_perfc_op table/enum mismatch");

void
ctxn_perfc_init(void)
{
    ctxn_perfc_op[PERFC_LT_CTXNOP_COMMIT].pcn_samplepct = 3;
}

void
ctxn_perfc_fini(void)
{
}
