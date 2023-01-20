/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include "cn/kvset.c"
#include "cndb/txn.h"

#define CHECK_TRUE(cond) if (!(cond)) {                                      \
                            fprintf(stderr, "Assert at line:%d\n", __LINE__); \
                                return merr(EBUG);                          \
                        }

MTF_BEGIN_UTEST_COLLECTION(cndb_txn_test);

static merr_t
process_cb(struct cndb_txn *tx, struct cndb_kvset *kvset, bool isadd, bool isacked, void *ctx)
{
    uint64_t num_kvsets = *(uint64_t *)ctx;

    CHECK_TRUE(isacked);
    if (kvset->ck_kvsetid <= num_kvsets / 2)
        CHECK_TRUE(!isadd);

    if (kvset->ck_kvsetid > num_kvsets / 2) {
        CHECK_TRUE(isadd);
        CHECK_TRUE(kvset->ck_nodeid == kvset->ck_kvsetid / 3);
    }

    free(kvset);
    return 0;
}

MTF_DEFINE_UTEST(cndb_txn_test, basic)
{
    merr_t err;
    uint64_t seqno = 100;
    uint64_t kblkid = 10;
    uint64_t vblkid = 11;
    struct cndb_txn *tx = 0;
    uint64_t num_kvsets = 1000;
    void *cookie[num_kvsets];
    struct kvset_meta km = {
        .km_dgen_hi = 2,
        .km_dgen_lo = 1,
    };

    err = cndb_txn_create(1, seqno, CNDB_INVAL_INGESTID, CNDB_INVAL_HORIZON,
                          (uint16_t)(num_kvsets / 2), (uint16_t)(num_kvsets / 2), &tx);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, tx);

    for (int i = num_kvsets - 1; i > num_kvsets / 2; i--) {
        ++kblkid;
        ++vblkid;
        err = cndb_txn_kvset_add(tx, 1, i, i / 3, &km, 1, 1, &kblkid, 1, &vblkid, &cookie[i]);
        ASSERT_EQ(0, err);
    }

    for (int i = num_kvsets / 2; i >= 0; i--) {
        err = cndb_txn_kvset_del(tx, 1, i, &cookie[i]);
        ASSERT_EQ(0, err);
    }

    for (int i = num_kvsets - 1; i >= 0; i--) {
        /* Test both variants of ack.
         */
        if (i % 2)
            err = cndb_txn_ack(tx, cookie[i], NULL);
        else
            err = cndb_txn_ack_by_kvsetid(tx, i, NULL);

        ASSERT_EQ(0, err);

        if (i > 0)
            ASSERT_EQ(false, cndb_txn_is_complete(tx));
        else
            ASSERT_EQ(true, cndb_txn_is_complete(tx));
    }

    err = cndb_txn_apply(tx, &process_cb, &num_kvsets);
    ASSERT_EQ(0, err);

    cndb_txn_destroy(tx);
}

MTF_END_UTEST_COLLECTION(cndb_txn_test)
