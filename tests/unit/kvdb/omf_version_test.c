/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_ikvdb/omf_version.h>

MTF_BEGIN_UTEST_COLLECTION(omf_version_test)

MTF_DEFINE_UTEST(omf_version_test, omf_version)
{
    /* This test fails if any OMF versions change.  The intent is to
     * catch errors when a low-level OMF version changes but the
     * global OMF version is not incremented.  However, this test is
     * not smart enough to do exactly that, so instead it simply fails
     * if any OMF versions change.  Whenever an OMF version changes,
     * this test will need to be updated accordingly.
     */

     /* Global OMF version */
    ASSERT_EQ(GLOBAL_OMF_VERSION, 4);

    /* Low-level OMF versions */
    ASSERT_EQ(CNDB_VERSION, 14);
    ASSERT_EQ(HBLOCK_HDR_VERSION, 1);
    ASSERT_EQ(KBLOCK_HDR_VERSION, 6);
    ASSERT_EQ(VBLOCK_HDR_VERSION, 2);
    ASSERT_EQ(BLOOM_OMF_VERSION, 5);
    ASSERT_EQ(WBT_TREE_VERSION, 6);
    ASSERT_EQ(CN_TSTATE_VERSION, 2);
    ASSERT_EQ(MBLOCK_METAHDR_VERSION, 2);
    ASSERT_EQ(MDC_LOGHDR_VERSION, 2);
    ASSERT_EQ(WAL_VERSION, 2);
    ASSERT_EQ(KVDB_META_VERSION, 2);
}

MTF_END_UTEST_COLLECTION(omf_version_test)
