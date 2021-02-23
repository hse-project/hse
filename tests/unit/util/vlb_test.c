/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/vlb.h>

#include <hse_ut/framework.h>

MTF_BEGIN_UTEST_COLLECTION(vlb_test);

MTF_DEFINE_UTEST(vlb_test, alloc)
{
    const int imax = VLB_CACHESZ_MAX / VLB_ALLOCSZ_MAX + 3;
    void *memv[imax];
    int i;

    /* Allocate a few more buffers over the cache size max,
     */
    for (i = 0; i < imax; ++i) {
        memv[i] = vlb_alloc(VLB_ALLOCSZ_MAX);
        ASSERT_NE(NULL, memv[i]);
    }

    /* cn requires buffers of at least 2x max value length.
     */
    ASSERT_TRUE(VLB_ALLOCSZ_MAX >= HSE_KVS_VLEN_MAX * 2);

    /* Free all buffers, not all will be cached.
     */
    for (i = 0; i < imax; ++i)
        vlb_free(memv[i], HSE_KVS_VLEN_MAX);


    /* Allocate and free a buffer, should come from cache.
     */
    ASSERT_TRUE(VLB_KEEPSZ_MAX + PAGE_SIZE < VLB_ALLOCSZ_MAX);

    memv[0] = vlb_alloc(VLB_KEEPSZ_MAX + PAGE_SIZE);
    ASSERT_NE(NULL, memv[0]);
    vlb_free(memv[0], VLB_KEEPSZ_MAX);


    /* Allocate and free a buffer over the max alloc size.
     */
    memv[0] = vlb_alloc(VLB_ALLOCSZ_MAX * 2);
    ASSERT_NE(NULL, memv[0]);
    vlb_free(memv[0], VLB_ALLOCSZ_MAX * 2);


    /* Try to allocate an impossibly large buffer.
     */
    memv[0] = vlb_alloc(ULONG_MAX);
    ASSERT_EQ(NULL, memv[0]);

    /* Freeing a NULL buffer shouldn't crash...
     */
    vlb_free(NULL, 0);
}

MTF_END_UTEST_COLLECTION(vlb_test)
