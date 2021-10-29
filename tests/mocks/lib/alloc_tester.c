/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2018 Micron Technology, Inc. All rights reserved.
 */

#include <mtf/conditions.h>
#include <mock/api.h>
#include <mock/alloc_tester.h>

/*
 * Example use of mapi_alloc_tester() to test function a create/destroy
 * function pair:
 *
 *   MTF_DEFINE_UTEST_PRE(test, cn_opencreate_nomem, pre)
 *   {
 *       struct xyz *s;
 *       merr_t err;
 *       int rc;
 *
 *       void run(struct mtf_test_info *lcl_ti, uint i, uint j) {
 *           err = xyz_create(rp, mp, db, &s);
 *           if (i == j)
 *               ASSERT_EQ(err, 0);
 *           else
 *               ASSERT_EQ(merr_errno(err), ENOMEM);
 *       }
 *
 *       void clean(struct mtf_test_info *lcl_ti) {
 *           if (!err)
 *               xyz_destroy(s);
 *       }
 *
 *       rc = mapi_alloc_tester(lcl_ti, run, clean);
 *       ASSERT_EQ(rc, 0);
 *   }
 *
 * mapi_alloc_tester() will first invoke run() with no injections and with
 * i==0 and j==0 to measure how many allocations were used.  It then loops to
 * call run() for i=(1..n_allocs) and j==n_allocs to test the failure
 * path for each allocation. For example, if 3 allocations are required,
 * run() will be invoked as follows:
 *
 *   run(lcl_ti, 0, 0);  // discover n_alloc == 3
 *   run(lcl_ti, 0, 3);  // inject failure on 1st allocation
 *   run(lcl_ti, 1, 3);  // ...
 *   run(lcl_ti, 2, 3);  // inject failure on 3rd allocation
 *   run(lcl_ti, 3, 3);  // inject failure on 4th allocation
 *
 * clean() is called after each run().  After each clean(), an ASSERT_EQ is
 * used to ensure number of allocations equals the number of calls to free().
 *
 * It is up to run() to verify status of xyz_create().  If i == j, then
 * xyz_create() should succeed, otherwise it should fail with an allocation
 * error.
 *
 * It is up to clean() to invoke xyz_destroy() only if the preceding
 * xyz_create() was successful.
 */
int
mapi_alloc_tester(
    struct mtf_test_info *      lcl_ti,
    mapi_alloc_tester_run_fn *  run,
    mapi_alloc_tester_clean_fn *clean)
{
    unsigned i, n_allocs;

    /* Determine number of allocations with no injected failures. */
    mapi_inject_unset(mapi_idx_malloc);
    mapi_inject_unset(mapi_idx_free);

    run(lcl_ti, 0, 0);

    n_allocs = mapi_calls(mapi_idx_malloc);

    if (clean)
        clean(lcl_ti);

    /* Skip loop if n_allocs is 0 since it would
     * invoke run() with the same parameters used
     * above and add no additional value.
     */
    if (!n_allocs)
        return 0;

    for (i = 0; i <= n_allocs; i++) {

        /* Fail on 1st, 2nd, etc allocation up to n_allocs */
        mapi_inject_unset(mapi_idx_malloc);
        mapi_inject_unset(mapi_idx_free);
        mapi_inject_once_ptr(mapi_idx_malloc, i + 1, 0);

        run(lcl_ti, i, n_allocs);

        if (clean)
            clean(lcl_ti);
    }

    mapi_inject_unset(mapi_idx_malloc);
    mapi_inject_unset(mapi_idx_free);
    return 0;
}
