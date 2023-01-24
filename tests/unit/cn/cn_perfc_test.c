/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>

#include <hse/util/platform.h>

#include "cn/cn_perfc_internal.h"

MTF_BEGIN_UTEST_COLLECTION(test);

#define PERFC_LT_FOOBAR 0

MTF_DEFINE_UTEST(test, t_cn_perfc_bkts)
{
    struct perfc_name pcn[1] = {
        NE(PERFC_LT_FOOBAR, 3, "bar", "bar"),
    };

    uint64_t edgev[3] = { 10, 20, 30 };
    int edgec = NELEM(edgev);

    cn_perfc_bkts_create(pcn, edgec, edgev, 7);
    cn_perfc_bkts_destroy(pcn);

    /* test a failure path during _create */
    cn_perfc_bkts_create(pcn, 0, edgev, 7);

    /* test specific branch in _destroy() */
    memset(pcn, 0, sizeof(*pcn));
    cn_perfc_bkts_destroy(pcn);
}

MTF_END_UTEST_COLLECTION(test)
