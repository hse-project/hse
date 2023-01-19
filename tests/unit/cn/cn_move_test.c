/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <cn/cn_tree_compact.h>
#include <cn/cn_tree_internal.h>
#include <cn/kvset.h>
#include <cn/move.h>
#include <mock/api.h>
#include <mocks/mock_kvset.h>
#include <mtf/framework.h>

#include <hse/util/platform.h>

int
pre(struct mtf_test_info *info)
{
    /* Default mock. */
    mock_kvset_set();

    /* Neuter the following APIs */
    mapi_inject(mapi_idx_cn_tree_get_cn, 0);
    mapi_inject(mapi_idx_cn_tree_get_cndb, 0);
    mapi_inject(mapi_idx_cn_tree_samp_update_move, 0);
    mapi_inject(mapi_idx_cndb_record_kvsetv_move, 0);
    mapi_inject(mapi_idx_route_map_delete, 0);

    return 0;
}

static void
init_node(struct cn_tree_node *tn, uint64_t nodeid)
{
    INIT_LIST_HEAD(&tn->tn_kvset_list);
    tn->tn_nodeid = nodeid;
    tn->tn_route_node = (void *)0x1234;
}

static merr_t
create_kvset(
    struct cn_tree *tree,
    struct cn_tree_node *tn,
    uint64_t kvsetid,
    uint64_t dgen_hi,
    uint64_t dgen_lo,
    uint32_t compc,
    struct kvset **kvset)
{
    struct kvset_meta km = { 0 };

    km.km_dgen_hi = dgen_hi;
    km.km_dgen_lo = dgen_lo;
    km.km_nodeid = tn->tn_nodeid;
    km.km_compc = compc;

    return kvset_open(tree, kvsetid, &km, kvset);
}

static uint
get_kvset_cnt(struct cn_tree_node *tn)
{
    struct list_head *node;
    uint cnt = 0;

    list_for_each (node, &tn->tn_kvset_list) {
        cnt++;
    }

    return cnt;
}

/* ------------------------------------------------------------
 * Unit tests
 */

MTF_BEGIN_UTEST_COLLECTION(move_test);

MTF_DEFINE_UTEST_PRE(move_test, empty_to_empty, pre)
{
    struct cn_tree tree = { 0 };
    struct cn_compaction_work w = { 0 };
    struct cn_tree_node sn = { 0 }, tn = { 0 };
    uint64_t nodeid = 0;
    merr_t err;

    err = rmlock_init(&tree.ct_lock);
    ASSERT_EQ(0, err);

    w.cw_tree = &tree;

    init_node(&sn, ++nodeid);
    init_node(&tn, ++nodeid);
    err = cn_move(&w, &sn, NULL, 0, true, &tn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(NULL, sn.tn_route_node);

    init_node(&sn, ++nodeid);
    init_node(&tn, ++nodeid);
    err = cn_move(&w, &sn, NULL, 0, false, &tn);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, sn.tn_route_node);

    rmlock_destroy(&tree.ct_lock);
}

MTF_DEFINE_UTEST_PRE(move_test, empty_to_non_empty, pre)
{
    struct cn_tree tree = { 0 };
    struct cn_compaction_work w = { 0 };
    struct cn_tree_node sn = { 0 }, tn = { 0 };
    struct kvset *ks;
    uint64_t kvsetid = 0, nodeid = 0;
    uint64_t dgen_hi = 100, dgen_lo = 50;
    uint32_t compc = 1;
    merr_t err;

    err = rmlock_init(&tree.ct_lock);
    ASSERT_EQ(0, err);

    w.cw_tree = &tree;

    init_node(&sn, ++nodeid);
    init_node(&tn, ++nodeid);

    err = create_kvset(&tree, &tn, ++kvsetid, dgen_hi, dgen_lo, compc, &ks);
    ASSERT_EQ(0, err);

    kvset_list_add_tail(ks, &tn.tn_kvset_list);
    kvset_set_work(ks, &w);

    err = cn_move(&w, &sn, NULL, 0, true, &tn);
    ASSERT_EQ(0, err);

    kvset_put_ref(ks);
    rmlock_destroy(&tree.ct_lock);
}

MTF_DEFINE_UTEST_PRE(move_test, non_empty_to_empty, pre)
{
    struct cn_tree tree = { 0 };
    struct cn_compaction_work w = { 0 };
    struct cn_tree_node sn = { 0 }, tn = { 0 };
    struct kvset_list_entry *src;
    const uint32_t num_kvsets = 2;
    struct kvset *ks[num_kvsets];
    uint32_t compc = 0;
    uint64_t kvsetid = 0, nodeid = 0;
    uint64_t dgen_hi = 100, dgen_lo = 50;
    merr_t err;

    err = rmlock_init(&tree.ct_lock);
    ASSERT_EQ(0, err);

    w.cw_tree = &tree;

    init_node(&sn, ++nodeid);
    init_node(&tn, ++nodeid);

    for (uint32_t i = 0; i < num_kvsets; i++) {
        err = create_kvset(&tree, &sn, ++kvsetid, dgen_hi - i, dgen_lo - i, compc + i, &ks[i]);
        ASSERT_EQ(0, err);
        kvset_list_add_tail(ks[i], &sn.tn_kvset_list);
        kvset_set_work(ks[i], &w);
    }

    /* Move 1 kvset from sn -> tn */
    src = list_first_entry_or_null(&sn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &sn, src, 1, false, &tn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, get_kvset_cnt(&sn));
    ASSERT_EQ(1, get_kvset_cnt(&tn));

    /* Reset workid */
    for (uint32_t i = 0; i < num_kvsets; i++)
        kvset_set_work(ks[i], &w);

    /* Move 1 kvset from sn -> tn */
    src = list_first_entry_or_null(&sn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &sn, src, 1, false, &tn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, get_kvset_cnt(&sn));
    ASSERT_EQ(2, get_kvset_cnt(&tn));

    /* Reset workid */
    for (uint32_t i = 0; i < num_kvsets; i++)
        kvset_set_work(ks[i], &w);

    /* Move 2 kvsets from tn -> sn */
    src = list_first_entry_or_null(&tn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &tn, src, 2, false, &sn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, get_kvset_cnt(&tn));
    ASSERT_EQ(2, get_kvset_cnt(&sn));

    for (uint32_t i = 0; i < num_kvsets; i++) {
        ASSERT_EQ(nodeid - 1, kvset_get_nodeid(ks[i]));
        kvset_put_ref(ks[i]);
    }
    rmlock_destroy(&tree.ct_lock);
}

MTF_DEFINE_UTEST_PRE(move_test, non_empty_to_non_empty, pre)
{
    struct cn_tree tree = { 0 };
    struct cn_compaction_work w = { 0 };
    struct cn_tree_node sn = { 0 }, tn = { 0 };
    struct kvset_list_entry *src;
    const uint32_t num_kvsets = 4;
    struct kvset *ks[num_kvsets];
    uint64_t kvsetid = 0, nodeid = 0;
    uint64_t dgen_hi = 100, dgen_lo = 50;
    uint32_t compc = 0;
    merr_t err;

    err = rmlock_init(&tree.ct_lock);
    ASSERT_EQ(0, err);

    w.cw_tree = &tree;

    init_node(&sn, ++nodeid);
    init_node(&tn, ++nodeid);

    for (uint32_t i = 0; i < num_kvsets / 2; i++) {
        dgen_hi -= i;
        dgen_lo -= i;
        compc += i;

        err = create_kvset(&tree, &sn, ++kvsetid, dgen_hi, dgen_lo, compc, &ks[i]);
        ASSERT_EQ(0, err);
        kvset_list_add_tail(ks[i], &sn.tn_kvset_list);
        kvset_set_work(ks[i], &w);
    }

    for (uint32_t i = num_kvsets / 2; i < num_kvsets; i++) {
        dgen_hi -= i;
        dgen_lo -= i;
        compc += i;

        err = create_kvset(&tree, &tn, ++kvsetid, dgen_hi, dgen_lo, compc, &ks[i]);
        ASSERT_EQ(0, err);
        kvset_list_add_tail(ks[i], &tn.tn_kvset_list);
        kvset_set_work(ks[i], &w);
    }

    /* Move 2 kvsets from sn -> tn */
    src = list_first_entry_or_null(&sn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &sn, src, 2, true, &tn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, get_kvset_cnt(&sn));
    ASSERT_EQ(4, get_kvset_cnt(&tn));

    /* Reset workid */
    for (uint32_t i = 0; i < num_kvsets; i++)
        kvset_set_work(ks[i], &w);

    /* Move 4 kvsets from tn -> sn */
    src = list_first_entry_or_null(&tn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &tn, src, 4, false, &sn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(4, get_kvset_cnt(&sn));
    ASSERT_EQ(0, get_kvset_cnt(&tn));

    for (uint32_t i = 0; i < num_kvsets; i++) {
        ASSERT_EQ(nodeid - 1, kvset_get_nodeid(ks[i]));
        kvset_put_ref(ks[i]);
    }
    rmlock_destroy(&tree.ct_lock);
}

MTF_DEFINE_UTEST_PRE(move_test, dgen_compc_order, pre)
{
    struct cn_tree tree = { 0 };
    struct cn_compaction_work w = { 0 };
    struct cn_tree_node sn = { 0 }, tn = { 0 };
    struct kvset_list_entry *src, *cur, *prev;
    const uint32_t num_kvsets = 6;
    struct kvset *ks[num_kvsets];
    uint64_t kvsetid = 0, nodeid = 0;
    uint64_t dgen_hi, dgen_lo;
    uint32_t compc = 0;
    merr_t err;

    err = rmlock_init(&tree.ct_lock);
    ASSERT_EQ(0, err);

    w.cw_tree = &tree;

    init_node(&sn, ++nodeid);
    init_node(&tn, ++nodeid);

    dgen_hi = 101;
    dgen_lo = 50;
    for (uint32_t i = 0; i < num_kvsets / 2; i++, dgen_hi--, dgen_lo--, compc++) {
        err = create_kvset(&tree, &sn, ++kvsetid, dgen_hi, dgen_lo, compc, &ks[i]);
        ASSERT_EQ(0, err);
        kvset_list_add_tail(ks[i], &sn.tn_kvset_list);
        kvset_set_work(ks[i], &w);
    }

    dgen_hi = 100;
    dgen_lo = 50;
    compc = 5;
    for (uint32_t i = num_kvsets / 2; i < num_kvsets; i++, dgen_hi--, compc++) {
        err = create_kvset(&tree, &tn, ++kvsetid, dgen_hi, dgen_lo, compc, &ks[i]);
        ASSERT_EQ(0, err);
        kvset_list_add_tail(ks[i], &tn.tn_kvset_list);
        kvset_set_work(ks[i], &w);
    }

    /* Move 2 kvsets from sn -> tn */
    src = list_first_entry_or_null(&sn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &sn, src, 2, false, &tn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(1, get_kvset_cnt(&sn));
    ASSERT_EQ(5, get_kvset_cnt(&tn));

    /* Reset workid */
    for (uint32_t i = 0; i < num_kvsets; i++)
        kvset_set_work(ks[i], &w);

    /* Move the remaining 1 kvset from sn -> tn */
    src = list_first_entry_or_null(&sn.tn_kvset_list, typeof(*src), le_link);
    err = cn_move(&w, &sn, src, 1, true, &tn);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, get_kvset_cnt(&sn));
    ASSERT_EQ(6, get_kvset_cnt(&tn));

    prev = NULL;
    list_for_each_entry (cur, &tn.tn_kvset_list, le_link) {
        if (prev) {
            ASSERT_LE(kvset_get_compc(prev->le_kvset), kvset_get_compc(cur->le_kvset));
            ASSERT_EQ(true, kvset_younger(prev->le_kvset, cur->le_kvset));
        }
        prev = cur;
    }

    for (uint32_t i = 0; i < num_kvsets; i++) {
        ASSERT_EQ(nodeid, kvset_get_nodeid(ks[i]));
        kvset_put_ref(ks[i]);
    }
    rmlock_destroy(&tree.ct_lock);
}

MTF_END_UTEST_COLLECTION(move_test)
