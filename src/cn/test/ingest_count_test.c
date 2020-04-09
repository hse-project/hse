/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_ikvdb/cn.h>
#include <mpool/mpool.h>

#include "../cn_internal.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

char data_path[PATH_MAX / 2];

int
test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *coll_info = info->ti_coll;

    hse_openlog("ingest_count_test", 1);

    if (coll_info->tci_argc > 1) {
        int len = strlen(coll_info->tci_argv[1]);

        if (coll_info->tci_argv[1][len - 1] == '/')
            coll_info->tci_argv[1][len - 1] = 0;
        strncpy(data_path, coll_info->tci_argv[1], sizeof(data_path) - 1);
    } else
        data_path[0] = 0;

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    return 0;
}

/* ------------------------------------------------------------
 * Unit tests
 */

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    ingest_count_test,
    test_collection_setup,
    test_collection_teardown);

MTF_DEFINE_UTEST(ingest_count_test, validate)
{
    FILE *   fp;
    char     buf[PATH_MAX], *bp;
    char *   av[12];
    int      ac, klen, nkey, nloop;
    unsigned best;
    int      verbose = !!getenv("DEBUG");

    snprintf(buf, sizeof(buf), "%s/%s", data_path, "wbtsize.8192");
    fp = fopen(buf, "r");
    ASSERT_TRUE(fp != 0);

    /* read wbtsize output, extract klen and nkey, test compute */
    nloop = 0;
    while (fgets(buf, sizeof(buf), fp)) {
        bp = buf;
        if (bp[0] == '#') /* ignore comments */
            continue;

        /*
         * validate input:
         * 1. we have at least 12 fields
         * 2. klen is within legal limts
         * 3. nkey is a reasonably large value
         */
        for (ac = 0; ac < 12; ++ac)
            av[ac] = strsep(&bp, " ");
        ASSERT_EQ(ac, 12);

        klen = atoi(av[1]);
        nkey = atoi(av[9]);
        ASSERT_TRUE(klen > 3 && klen < 1025);
        ASSERT_TRUE(nkey > 10000);

        best = cn_best_ingest_count(0, klen);
        if (verbose)
            printf("klen %d  nkey %d  best %d\n", klen, nkey, best);

        /*
         * verify:
         * 1. it is not above the threshold
         * 2. it is a reasonably large value
         * 3. it is within 10% of the threshold
         */
        ASSERT_TRUE(nkey > best);
        ASSERT_TRUE(best > 10000 && best < 2 * 1000 * 1000);
        ASSERT_TRUE(nkey - best < nkey / 10);
        ++nloop;
    }

    /* ensure we have done a reasonable number of samples */
    ASSERT_TRUE(nloop > 1000);
    fclose(fp);
}

MTF_DEFINE_UTEST(ingest_count_test, set_maint)
{
    struct cn          cn = {};
    struct kvs_rparams rp;

    rp = kvs_rparams_defaults();
    cn.rp = &rp;

    cn_disable_maint(&cn, true);

    ASSERT_EQ(rp.cn_maint_disable, true);

    cn_disable_maint(&cn, false);

    ASSERT_EQ(rp.cn_maint_disable, false);

    cn_disable_maint(&cn, true);

    ASSERT_EQ(rp.cn_maint_disable, true);
}

MTF_END_UTEST_COLLECTION(ingest_count_test)
