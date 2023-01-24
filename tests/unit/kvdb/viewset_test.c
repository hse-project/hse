/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/test/mtf/framework.h>
#include <hse/test/mock/api.h>
#include <hse/test/mock/alloc_tester.h>

#include "kvdb/viewset.h"

#include <pthread.h>
#include <stdio.h>
#include <sys/sysinfo.h>
#include <unistd.h>
#include <hse/ikvdb/limits.h>

MTF_BEGIN_UTEST_COLLECTION(viewset_test)

MTF_DEFINE_UTEST(viewset_test, t_viewset_create)
{
    struct viewset *vs;
    merr_t         err;
    atomic_ulong   seqno;
    atomic_ulong   tseqno;

    err = viewset_create(&vs, &seqno, &tseqno);
    ASSERT_EQ(err, 0);

    viewset_destroy(vs);
}

#ifndef __clang__
MTF_DEFINE_UTEST(viewset_test, t_viewset_create_enomem)
{
    struct viewset *vs;
    merr_t          err;
    atomic_ulong    seqno;
    atomic_ulong    tseqno;
    int             rc;

    void run(struct mtf_test_info * lcl_ti, uint i, uint j)
    {
        err = viewset_create(&vs, &seqno, &tseqno);
        if (i == j)
            ASSERT_EQ(err, 0);
        else
            ASSERT_EQ(merr_errno(err), ENOMEM);
    }

    void clean(struct mtf_test_info * lcl_ti)
    {
        if (!err)
            viewset_destroy(vs);
    }

    rc = mapi_alloc_tester(lcl_ti, run, clean);
    ASSERT_EQ(rc, 0);
}
#endif

MTF_DEFINE_UTEST(viewset_test, t_viewset_insert)
{
    struct viewset *vs;
    atomic_ulong    vs_seqno;
    atomic_ulong    vs_tseqno;
    long            start_seqno;
    merr_t          err;
    int             show;
    int             inserted;
    int             max_inserts;
    void          **cookies;
    uint64_t       *views, tseqno;

    start_seqno = 1234;
    atomic_set(&vs_seqno, start_seqno);

    show = 10;
    inserted = 0;
    max_inserts = HSE_VIEWSET_ELTS_MAX + 1;
    cookies = mapi_safe_calloc(max_inserts, sizeof(*cookies));
    ASSERT_NE(cookies, NULL);

    views = mapi_safe_calloc(max_inserts, sizeof(*views));
    ASSERT_NE(views, NULL);

    err = viewset_create(&vs, &vs_seqno, &vs_tseqno);
    ASSERT_EQ(err, 0);

    ASSERT_EQ(viewset_horizon(vs), start_seqno);

    for (int i = 0; i < max_inserts; i++) {
        err = viewset_insert(vs, &views[i], &tseqno, &cookies[i]);
        if (err) {
            ASSERT_EQ(merr_errno(err), ENOMEM);
            break;
        }
        ASSERT_EQ(err, 0);
        ASSERT_EQ(views[i], start_seqno + i);
        ASSERT_NE(cookies[i], NULL);
        inserted++;
        if (i < show)
            printf("insert %5u with view %5lu --> viewset_horizon %lu\n",
                i, views[i], viewset_horizon(vs));
        ASSERT_EQ(viewset_horizon(vs), start_seqno);

        if (inserted % 500)
            usleep(1);
    }

    ASSERT_GT(inserted, 0);

    printf("...\ninsert %5u with view %5lu --> viewset_horizon %lu\n",
        inserted-1, views[inserted-1], viewset_horizon(vs));

    ASSERT_LT(inserted, max_inserts);

    for (int i = 0; i < inserted; i++) {
        uint32_t min_changed;
        uint64_t min_view_sn;
        viewset_remove(vs, cookies[i], &min_changed, &min_view_sn);
        if (i < show)
            printf("remove %5u with view %5lu --> viewset_horizon %lu\n",
                i, views[i], viewset_horizon(vs));
        ASSERT_EQ(viewset_horizon(vs), start_seqno + i + 1);
    }

    printf("...\nremove %5u with view %5lu --> viewset_horizon %lu\n",
        inserted-1, views[inserted-1], viewset_horizon(vs));

    viewset_destroy(vs);
    mapi_safe_free(views);
    mapi_safe_free(cookies);
}


MTF_END_UTEST_COLLECTION(viewset_test);
