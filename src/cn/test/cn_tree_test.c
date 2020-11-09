/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/platform.h>

#include <hse/hse_limits.h>

#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/cn_node_loc.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/cn.h>

#include "../cn_tree.h"
#include "../cn_tree_iter.h"
#include "../cn_tree_internal.h"
#include "../cn_tree_create.h"
#include "../cn_tree_compact.h"

#include "../cn_internal.h"
#include "../kvset.h"
#include "../kv_iterator.h"

struct mpool *     mock_ds = (void *)0x1234abcd;
struct kvdb_health mock_health;
struct kvs_rparams rp_struct, *rp;

#define KVSET_FAKE_PTR 0x1234f000

/*----------------------------------------------------------------
 * Mocked kvset
 */
struct fake_kvset {
    struct kvset_list_entry kle;
    u32                     node_level;
    u32                     node_offset;
    u32                     timestamp;
    u32                     kvsets_in_node;
    u32                     nk;
    u32                     nv;
    u64                     dgen;
    u64                     vused;
    u64                     workid;
    struct kvset_stats      stats;
    struct fake_kvset *     next;
};

const struct kvset_stats fake_kvset_stats = {

    .kst_keys = 10000,
    .kst_kvsets = 1,

    .kst_kblks = 1,
    .kst_vblks = 1,

    .kst_kalen = 32 * 1024 * 1024,
    .kst_kwlen = 30 * 1024 * 1024,

    .kst_valen = 32 * 1024 * 1024,
    .kst_vwlen = 30 * 1024 * 1024,
    .kst_vulen = 10 * 1024 * 1024,
};

const struct kvset_stats *
_kvset_statsp(const struct kvset *ks)
{
    return &fake_kvset_stats;
}

void
_kvset_stats(const struct kvset *ks, struct kvset_stats *stats)
{
    *stats = fake_kvset_stats;
}

/* Fake kvsets are created directly by this unit test and manually placed into
 * the cn_tree.  When the code under test calls kvset_create() (e.g., from
 * cn_compaction_update_tree()) it will hit the mapi_inject mock that simply
 * returns 0 (success).
 */
static struct fake_kvset *
fake_kvset_create(struct fake_kvset **head, u64 dgen)
{
    struct fake_kvset *kvset;

    kvset = mapi_safe_malloc(sizeof(struct fake_kvset));
    if (!kvset)
        return 0;

    memset(kvset, 0, sizeof(*kvset));
    kvset->kle.le_kvset = (void *)kvset;

    kvset->nk = 1;
    kvset->nv = 1;
    kvset->dgen = dgen;

    /* add to front of list */
    if (head) {
        kvset->next = *head;
        *head = kvset;
    }

    return kvset;
}

static struct fake_kvset *
fake_kvset_create_add(
    struct fake_kvset **head,
    struct cn_tree *    tree,
    u32                 node_level,
    u32                 node_offset,
    u64                 dgen)
{
    struct fake_kvset *kvset;
    merr_t             err;

    kvset = fake_kvset_create(head, dgen);
    if (!kvset)
        return 0;

    kvset->node_level = node_level;
    kvset->node_offset = node_offset;

    err = cn_tree_insert_kvset(tree, (struct kvset *)kvset, node_level, node_offset);
    if (err) {
        if (head)
            *head = kvset->next;
        free(kvset);
        return 0;
    }

    return kvset;
}

static void
fake_kvset_destroy(struct fake_kvset *kvset)
{
    mapi_safe_free(kvset);
}

static u64
_kvset_get_dgen(struct kvset *handle)
{
    return ((struct fake_kvset *)handle)->dgen;
}

static uint
_kvset_get_compc(struct kvset *handle)
{
    return 0;
}

static u64
_kvset_get_workid(struct kvset *handle)
{
    return ((struct fake_kvset *)handle)->workid;
}

static void
_kvset_set_workid(struct kvset *handle, u64 id)
{
    ((struct fake_kvset *)handle)->workid = id;
}

static u32
_kvset_get_num_kblocks(struct kvset *handle)
{
    return ((struct fake_kvset *)handle)->nk;
}

static u32
_kvset_get_num_vblocks(struct kvset *handle)
{
    return ((struct fake_kvset *)handle)->nv;
}

void
_kvset_get_max_key(struct kvset *ks, void **key, uint *klen)
{
    *key = "foo";
    *klen = 3;
}

/*----------------------------------------------------------------
 * Mocked kvset iterator
 */

static void
_kvset_iter_release(struct kv_iterator *);

static struct kv_iterator_ops mocked_kvset_iter_ops = {
    .kvi_release = _kvset_iter_release,
};

struct mocked_kvset_iter {
    struct kv_iterator handle;
    struct fake_kvset *kvset;
};

static merr_t
_kvset_iter_create(
    struct kvset *           kvset,
    struct workqueue_struct *workq,
    struct workqueue_struct *vra_wq,
    struct perfc_set *       pc,
    enum kvset_iter_flags    flags,
    struct kv_iterator **    handle)
{
    struct mocked_kvset_iter *mk;

    mk = mapi_safe_calloc(1, sizeof(*mk));
    if (!mk)
        return merr(EBUG);

    mk->kvset = (struct fake_kvset *)kvset;
    mk->handle.kvi_ops = &mocked_kvset_iter_ops;
    *handle = &mk->handle;
    return 0;
}

static void *
_kvset_from_iter(struct kv_iterator *handle)
{
    return ((struct mocked_kvset_iter *)handle)->kvset;
}

static void
_kvset_iter_release(struct kv_iterator *h)
{
    struct mocked_kvset_iter *mk;

    if (!h)
        return;

    mk = container_of(h, typeof(*mk), handle);
    mapi_safe_free(mk);
}

/*----------------------------------------------------------------
 * Injections
 */

struct injections {
    u64 rc;
    u32 api;
};

struct injections injections[] = {

    /* kvset: fake success */
    { 0, mapi_idx_kvset_create },
    { 0, mapi_idx_kvset_put_ref },
    { 0, mapi_idx_kvset_get_ref },
    { 0, mapi_idx_kvset_log_d_records },
    { 0, mapi_idx_kvset_mark_mblocks_for_delete },
    { 0, mapi_idx_kvset_madvise_kblks },
    { 0, mapi_idx_kvset_madvise_kmaps },
    { 0, mapi_idx_kvset_madvise_vblks },
    { 0, mapi_idx_kvset_madvise_vmaps },
    { 0, mapi_idx_kvset_get_scatter_score },

    /* kvset: fake failure */
    { 929523521341, mapi_idx_kvset_ctime },
    { KVSET_MISS_KEY_TOO_SMALL, mapi_idx_kvset_kblk_start },
    { 1234, mapi_idx_kvset_get_seqno_max },
    { 0, mapi_idx_kvset_get_hlog },
    { 0, mapi_idx_kvset_get_vbsetv },

    /* cn: fake success */
    { 0, mapi_idx_cn_kcompact },
    { 0, mapi_idx_cn_spill },
    { 0, mapi_idx_cn_mblocks_commit },
    { 0, mapi_idx_cn_mblocks_destroy },
    { 0, mapi_idx_cn_get_flags },
    { 10, mapi_idx_cn_get_seqno_horizon },
    { 0, mapi_idx_cn_get_cancel },
    { 0, mapi_idx_cn_get_flags },
    { 0, mapi_idx_cn_get_sched },
    { 0, mapi_idx_cn_get_maint_wq },
    { 0, mapi_idx_cn_inc_ingest_dgen },

    /* csched */
    { 0, mapi_idx_csched_notify_ingest },

    /* cndb: fake success */
    { 0, mapi_idx_cndb_txn_start },
    { 0, mapi_idx_cndb_txn_txc },
    { 0, mapi_idx_cndb_txn_txd },
    { 0, mapi_idx_cndb_txn_meta },
    { 0, mapi_idx_cndb_txn_ack_c },
    { 0, mapi_idx_cndb_txn_ack_d },
    { 0, mapi_idx_cndb_txn_nak },

    { 0, mapi_idx_hlog_create },
    { 0, mapi_idx_hlog_destroy },
    { 0, mapi_idx_hlog_reset },
    { 0, mapi_idx_hlog_data },
    { 0, mapi_idx_hlog_union },
    { 0, mapi_idx_hlog_precision },
    { 0, mapi_idx_hlog_add },
    { 0, mapi_idx_hlog_card },

    { 0, mapi_idx_ikvdb_get_csched },

    /* kvset mblock ids */
    { 0xabc001, mapi_idx_kvset_get_nth_kblock_id },
    { 0xabc002, mapi_idx_kvset_get_nth_vblock_id },
    { 128 * 1024, mapi_idx_kvset_get_nth_vblock_len },

    /* we need kvset_iter_create, but we should never
     * need the guts of an iterator b/c we mock
     * the actual compact/spill functions. */
    { 0, mapi_idx_kvset_iter_set_stats },
    { -1, mapi_idx_kvset_iter_seek },
    { -1, mapi_idx_kvset_iter_next_key },
    { -1, mapi_idx_kvset_iter_next_val },
    { -1, mapi_idx_kvset_iter_next_vref },
};

static int
preload(struct mtf_test_info *lcl_ti)
{
    hse_openlog("cn_tree_test", 1);
    hse_log_set_squelch_ns(0);
    return 0;
}

static int
postload(struct mtf_test_info *lcl_ti)
{
    return 0;
}

static int
test_setup(struct mtf_test_info *lcl_ti)
{
    int i;

    for (i = 0; i < NELEM(injections); i++)
        mapi_inject(injections[i].api, injections[i].rc);

    MOCK_SET(kvset, _kvset_iter_create);
    MOCK_SET(kvset, _kvset_from_iter);

    mapi_inject(mapi_idx_cn_mpool_dev_zone_alloc_unit_default, 32 << 20);

    MOCK_SET(kvset, _kvset_get_compc);
    MOCK_SET(kvset, _kvset_get_max_key);
    MOCK_SET(kvset, _kvset_statsp);
    MOCK_SET(kvset, _kvset_stats);

    MOCK_SET(kvset, _kvset_get_workid);
    MOCK_SET(kvset, _kvset_set_workid);

    MOCK_SET(kvset_view, _kvset_get_dgen);
    MOCK_SET(kvset_view, _kvset_get_num_kblocks);
    MOCK_SET(kvset_view, _kvset_get_num_vblocks);

    memset(&mock_health, 0, sizeof(mock_health));

    rp_struct = kvs_rparams_defaults();
    rp = &rp_struct;

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(test, preload, postload);

MTF_DEFINE_UTEST_PRE(test, t_create_error_paths, test_setup)
{
    merr_t             err;
    struct cn_tree *   tree = 0;
    u32                api = mapi_idx_malloc;
    struct kvs_cparams cp;

    /* fanout of 0 is invalid */
    memset(&cp, 0, sizeof(cp));
    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_TRUE(err);

    /* huge fanouts are invalid */
    cp.cp_fanout = 100;
    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_TRUE(err);

    /* pfx_len greater than HSE_KVS_MAX_PFXLEN is invalid */
    cp.cp_fanout = 1 << 3;
    cp.cp_pfx_len = HSE_KVS_MAX_PFXLEN + 1;
    cp.cp_pfx_pivot = 2;
    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_TRUE(err);

    /* memory allocation */
    mapi_inject_once_ptr(api, 1, 0);
    memset(&cp, 0, sizeof(cp));
    cp.cp_fanout = 1 << 2;
    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_EQ(merr_errno(err), ENOMEM);

    /* memory allocation - khashmap */
    mapi_inject_once_ptr(api, 1, 0);
    memset(&cp, 0, sizeof(cp));
    cp.cp_fanout = 1 << 2;
    err = cn_tree_create(&tree, (void *)1, 0, &cp, &mock_health, rp);
    ASSERT_EQ(merr_errno(err), ENOMEM);
    mapi_inject_unset(api);
}

MTF_DEFINE_UTEST_PRE(test, t_destroy_null_ptr, test_setup)
{
    /* This seems like a useless test b/c there are no asserts,
     * but it increases branch coverage in cn_tree_destroy

     */
    cn_tree_destroy(NULL);
}

MTF_DEFINE_UTEST_PRE(test, t_simple_api, test_setup)
{
    merr_t err;

    struct cn_tree *    tree = 0;
    struct kvs_cparams *out,
        cp = {.cp_sfx_len = 0, .cp_pfx_len = 12, .cp_fanout = 8, .cp_pfx_pivot = 0 };

    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_EQ(err, 0);
    ASSERT_NE(tree, NULL);

    out = cn_tree_get_cparams(tree);
    ASSERT_EQ(8, out->cp_fanout);
    ASSERT_EQ(12, out->cp_pfx_len);

    ASSERT_EQ(0, cn_tree_initial_dgen(tree));

    cn_tree_set_initial_dgen(tree, 42);

    ASSERT_EQ(42, cn_tree_initial_dgen(tree));

    cn_tree_destroy(tree);
}

/*----------------------------------------------------------------
 * Test cn_tree_find_parent_child_link() by way of cn_tree_create_node().
 */
MTF_DEFINE_UTEST_PRE(test, t_cn_tree_create_node, test_setup)
{
    merr_t          err;
    struct cn_tree *tree;
    uint            max_depth, depth, off;
    uint            fan, fbits;
    uint            api;

    for (fbits = CN_FANOUT_BITS_MIN; fbits <= CN_FANOUT_BITS_MAX; fbits++) {
        struct kvs_cparams cp = { 0 };

        fan = 1 << fbits;
        max_depth = cn_tree_max_depth(fbits);

        cp.cp_fanout = fan;
        cp.cp_sfx_len = 0;
        err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
        ASSERT_EQ(err, 0);

        /* create root to leaf on left side of tree */
        for (depth = 0; depth <= max_depth; depth++) {
            err = cn_tree_create_node(tree, depth, 0, 0);
            ASSERT_EQ(err, 0);
        }

        /* create leaf to root */
        for (depth = max_depth + 1; depth-- > 0;) {

            /* invalid node offset. */
            off = nodes_in_level(fbits, depth);
            err = cn_tree_create_node(tree, depth, off, 0);
            ASSERT_EQ(merr_errno(err), EINVAL);

            /* right side of tree */
            off = nodes_in_level(fbits, depth) - 1;
            err = cn_tree_create_node(tree, depth, off, 0);
            ASSERT_EQ(err, 0);

            /* middle of tree */
            if (depth > 1) {
                off = fan * depth - 1;
                err = cn_tree_create_node(tree, depth, off, 0);
                ASSERT_EQ(err, 0);
            }
        }

        /* invalid node level */
        err = cn_tree_create_node(tree, depth, 0, 0);
        ASSERT_EQ(merr_errno(err), EINVAL);

        cn_tree_destroy(tree);
    }

    struct kvs_cparams cp = {
        .cp_fanout = 16,
    };

    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_EQ(err, 0);

    cn_tree_setup(tree, mock_ds, (void *)0x1234, rp, (void *)0x5678, 10, (void *)0x9abc);
    ASSERT_EQ(0x9abc, cn_tree_get_cnkvdb(tree));
    ASSERT_EQ(mock_ds, cn_tree_get_ds(tree));
    ASSERT_EQ(rp, cn_tree_get_rp(tree));
    ASSERT_EQ(0x5678, cn_tree_get_cndb(tree));
    ASSERT_EQ(10, cn_tree_get_cnid(tree));
    ASSERT_EQ(1 << 4, (cn_tree_get_cparams(tree))->cp_fanout);

    /* allocation failure */
    api = mapi_idx_kmem_cache_zalloc;
    mapi_inject_once_ptr(api, 1, NULL);
    err = cn_tree_create_node(tree, 1, 1, 0);
    ASSERT_EQ(merr_errno(err), ENOMEM);
    mapi_inject_unset(api);

    cn_tree_destroy(tree);
}

MTF_DEFINE_UTEST_PRE(test, t_cn_tree_ingest_update, test_setup)
{
    struct cn_tree *         tree;
    struct cn_tree_node *    node;
    struct cn_node_loc       loc;
    merr_t                   err;
    u32                      fanout_bits = 2;
    struct kvset *           kvsetv[4];
    struct kvset_list_entry *le;
    uint                     i;

    struct kvs_cparams cp = {
        .cp_fanout = 1 << fanout_bits,
    };

    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_EQ(err, 0);

    for (i = 0; i < NELEM(kvsetv); i++) {
        kvsetv[i] = (struct kvset *)fake_kvset_create(0, 100 + i);
        ASSERT_NE(NULL, kvsetv[i]);

        cn_tree_ingest_update(tree, kvsetv[i], 0, 0, 0);
    }

    /* we should find kvset in root node */
    loc.node_level = 0;
    loc.node_offset = 0;
    node = cn_tree_find_node(tree, &loc);
    ASSERT_NE(node, NULL);

    /* verify kvsets */
    le = list_last_entry_or_null(&node->tn_kvset_list, struct kvset_list_entry, le_link);
    for (i = 0; i < NELEM(kvsetv); i++) {
        ASSERT_EQ(le->le_kvset, kvsetv[i]);
        le = list_prev_entry_or_null(le, le_link, &node->tn_kvset_list);
    }
    /* Should be at end of list */
    ASSERT_TRUE(le == 0);

    INIT_LIST_HEAD(&node->tn_kvset_list);
    cn_tree_destroy(tree);

    for (i = 0; i < NELEM(kvsetv); i++)
        fake_kvset_destroy((struct fake_kvset *)kvsetv[i]);
}

/*----------------------------------------------------------------
 * Support for the MY_TEST1 and MY_TEST2 macros below
 */
struct test_params {
    u64 fanout_bits;
    u64 levels;
    int verbose;
};

struct iter_verify {
    u32  counter;
    u32  prev_node_level;
    u32  prev_node_offset;
    u32  prev_kvset_timestamp;
    bool order_oldest_first;
};

struct test {
    struct mtf_test_info *mtf;
    struct test_params    p;
    struct iter_verify    iter;
    struct fake_kvset *   kvset_list;
    struct cn_tree *      tree;
};

static void
test_init(struct test *t, struct test_params *params, struct mtf_test_info *lcl_ti)
{
    memset(t, 0, sizeof(*t));
    t->p = *params;
    t->mtf = lcl_ti;
}

static u32
num_kvsets_in_node(u32 node_level, u32 node_offset)
{
    return 1 + node_offset % 3;
}

static int
tree_iter_callback(
    void *               rock,
    struct cn_tree *     tree,
    struct cn_tree_node *node,
    struct cn_node_loc * loc,
    struct kvset *       handle)
{
    struct test *         t = (struct test *)rock;
    struct mtf_test_info *lcl_ti = t->mtf;
    struct fake_kvset *   kvset = (struct fake_kvset *)handle;

    if (!handle)
        return 0;

    if (t->p.verbose) {
        hse_log(HSE_INFO "node; level %2u, offset %4u", loc->node_level, loc->node_offset);
    }

    ASSERT_EQ_RET(kvset->node_level, loc->node_level, 1);
    ASSERT_EQ_RET(kvset->node_offset, loc->node_offset, 1);
    ASSERT_EQ_RET(kvset->kvsets_in_node, num_kvsets_in_node(loc->node_level, loc->node_offset), 1);

    /* kvsets within a node must be returned in order from newest
     * to oldest */
    if (t->iter.counter > 0) {
        if (t->iter.prev_node_level == loc->node_level &&
            t->iter.prev_node_offset == loc->node_offset) {
            u32 prev_timestamp = t->iter.prev_kvset_timestamp;
            u32 curr_timestamp = kvset->timestamp;

            if (t->iter.order_oldest_first) {
                ASSERT_LT_RET(prev_timestamp, curr_timestamp, 1);
            } else {
                ASSERT_GT_RET(prev_timestamp, curr_timestamp, 1);
            }
        }
    }

    t->iter.prev_node_level = loc->node_level;
    t->iter.prev_node_offset = loc->node_offset;
    t->iter.prev_kvset_timestamp = kvset->timestamp;

    t->iter.counter++;
    return 0;
}

struct kvs_cparams cp;

static int
test_tree_create(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;

    merr_t             err;
    uint               lx, nx, kx;
    struct fake_kvset *kvset;

    cp.cp_fanout = 1 << t->p.fanout_bits;

    err = cn_tree_create(&t->tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_TRUE_RET(err == 0, -1);
    ASSERT_TRUE_RET(t->tree != 0, -1);

    for (lx = 0; lx < t->p.levels; lx++) {
        uint nodes_in_level = 1 << (t->p.fanout_bits * lx);

        for (nx = 0; nx < nodes_in_level; nx++) {
            uint num_kvsets_this_node = num_kvsets_in_node(lx, nx);

            if (t->p.verbose)
                hse_log(HSE_INFO "add %3u kvsets to node (%2u,%4u)", num_kvsets_this_node, lx, nx);
            for (kx = 0; kx < num_kvsets_this_node; kx++) {
                kvset = fake_kvset_create_add(&t->kvset_list, t->tree, lx, nx, 100 + kx);
                ASSERT_TRUE_RET(kvset != NULL, -1);
                kvset->timestamp = kx + 1000;
                kvset->kvsets_in_node = num_kvsets_this_node;
            }
        }
    }

    return 0;
}

static int
test_tree_check_with_iters(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;

    /* check iter w/ order = oldest kvset first */
    memset(&t->iter, 0, sizeof(t->iter));
    t->iter.order_oldest_first = 1;
    cn_tree_preorder_walk(t->tree, KVSET_ORDER_OLDEST_FIRST, tree_iter_callback, t);

    /* check iter w/ order = newest kvset first */
    memset(&t->iter, 0, sizeof(t->iter));
    t->iter.order_oldest_first = 0;
    cn_tree_preorder_walk(t->tree, KVSET_ORDER_NEWEST_FIRST, tree_iter_callback, t);

    /* check iter when created at a non-root node */
    if (t->p.levels > 2) {
        struct cn_tree_node *tn;
        int                  visited, expected;
        struct tree_iter     ti;
        uint                 lx;

        tree_iter_init(t->tree, &ti, TRAVERSE_TOPDOWN);

        tn = tree_iter_next(t->tree, &ti);
        tn = tree_iter_next(t->tree, &ti);
        tn = tree_iter_next(t->tree, &ti);

        /* create iterator at third node from the traversal */
        tree_iter_init_node(t->tree, &ti, TRAVERSE_TOPDOWN, tn);

        expected = 0;
        for (lx = 1; lx < t->p.levels - tn->tn_loc.node_level; lx++)
            expected += 1 << (t->p.fanout_bits * lx);
        expected += 1;

        visited = 0;
        while ((tn = tree_iter_next(t->tree, &ti)))
            ++visited;

        /* calculate expected nodes in subtree */
        ASSERT_TRUE_RET(expected == visited, -1);
    }

    return 0;
}

static void
test_tree_destroy(struct test *t)
{
    struct fake_kvset *kvset;

    cn_tree_destroy(t->tree);
    t->tree = 0;

    while (t->kvset_list) {
        kvset = t->kvset_list;
        t->kvset_list = kvset->next;
        fake_kvset_destroy(kvset);
    }
}

static void
test_tree(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;
    merr_t                err;

    err = test_tree_create(t);
    ASSERT_TRUE(err == 0);

    err = test_tree_check_with_iters(t);
    ASSERT_TRUE(err == 0);

    test_tree_destroy(t);
}

static void
create(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;
    merr_t                err;
    struct cn_tree *      tree = 0;

    struct kvs_cparams cp = {
        .cp_fanout = 1 << t->p.fanout_bits,
    };

    err = cn_tree_create(&tree, NULL, 0, &cp, &mock_health, rp);
    ASSERT_TRUE(err == 0);

    cn_tree_destroy(tree);
}

static void
cn_comp_work_completion(struct cn_compaction_work *w)
{
}

static void
cn_comp_work_init(
    struct test *              t,
    struct cn_tree_node *      tn,
    struct cn_compaction_work *w,
    enum cn_action             action,
    bool                       use_token)
{
    struct kvset_list_entry *le;
    struct list_head *       head = &tn->tn_kvset_list;
    struct kvset_stats *     stats;

    memset(w, 0, sizeof(*w));

    w->cw_ds = mock_ds;
    w->cw_rp = rp;

    w->cw_tree = t->tree;
    w->cw_node = tn;

    /* walk from tail (oldest), skip kvsets that are busy */
    for (le = list_last_entry(head, typeof(*le), le_link); &le->le_link != head;
         le = list_prev_entry(le, le_link)) {

        if (!w->cw_mark) {
            w->cw_mark = le;
            w->cw_dgen_lo = kvset_get_dgen(le->le_kvset);
        }

        kvset_set_workid(le->le_kvset, w->cw_dgen_lo);

        w->cw_dgen_hi = kvset_get_dgen(le->le_kvset);

        stats = kvset_statsp(le->le_kvset);
        w->cw_nk += stats->kst_kblks;
        w->cw_nv += stats->kst_vblks;

        w->cw_kvset_cnt++;
    }

    cn_node_stats_get(tn, &w->cw_ns);
    w->cw_completion = cn_comp_work_completion;

    w->cw_action = action;
    w->cw_have_token = use_token;
    if (w->cw_have_token)
        cn_node_comp_token_get(tn);
}

MTF_DEFINE_UTEST_PRE(test, t_cn_comp, test_setup)
{
    enum cn_action action;
    int            use_token;
    int            cancel;

    for (action = CN_ACTION_NONE; action < CN_ACTION_END; action++) {

        for (use_token = 0; use_token < 2; use_token++) {

            for (cancel = 0; cancel < 2; cancel++) {

                struct test_params tp = {};
                struct test        t = {};
                merr_t             err;

                struct cn_tree_node *     tn;
                struct cn_compaction_work w;

                tp.fanout_bits = 4;
                tp.levels = 2;

                test_init(&t, &tp, lcl_ti);

                err = test_tree_create(&t);
                ASSERT_TRUE(err == 0);

                err = test_tree_check_with_iters(&t);
                ASSERT_TRUE(err == 0);

                /* Second child in level 1 has 3 kvsets */
                tn = t.tree->ct_root->tn_childv[2];

                cn_comp_work_init(&t, tn, &w, action, use_token);

                if (cancel)
                    cn_comp_cancel_cb(&w.cw_job);
                else
                    cn_comp_slice_cb(&w.cw_job);

                test_tree_destroy(&t);
            }
        }
    }
}

#define MY_TEST1(NAME, N1, V1, VERBOSE)                     \
    MTF_DEFINE_UTEST_PRE(test, NAME##_##N1##V1, test_setup) \
    {                                                       \
        struct test_params tp = {                           \
            .N1 = V1, .verbose = VERBOSE,                   \
        };                                                  \
        struct test test;                                   \
                                                            \
        test_init(&test, &tp, lcl_ti);                      \
        NAME(&test);                                        \
    }

#define MY_TEST2(NAME, N1, V1, N2, V2, VERBOSE)                        \
    MTF_DEFINE_UTEST_PRE(test, NAME##_##N1##V1##_##N2##V2, test_setup) \
    {                                                                  \
        struct test_params tp = {                                      \
            .N1 = V1, .N2 = V2, .verbose = VERBOSE,                    \
        };                                                             \
        struct test test;                                              \
                                                                       \
        test_init(&test, &tp, lcl_ti);                                 \
        NAME(&test);                                                   \
    }

MY_TEST1(create, fanout_bits, 1, 0);
MY_TEST1(create, fanout_bits, 2, 0);
MY_TEST1(create, fanout_bits, 3, 0);
MY_TEST1(create, fanout_bits, 4, 0);

MY_TEST2(test_tree, fanout_bits, 1, levels, 1, 1);
MY_TEST2(test_tree, fanout_bits, 1, levels, 2, 1);
MY_TEST2(test_tree, fanout_bits, 1, levels, 3, 0);
MY_TEST2(test_tree, fanout_bits, 1, levels, 4, 0);

MY_TEST2(test_tree, fanout_bits, 2, levels, 1, 0);
MY_TEST2(test_tree, fanout_bits, 2, levels, 3, 1);

MY_TEST2(test_tree, fanout_bits, 3, levels, 1, 0);
MY_TEST2(test_tree, fanout_bits, 3, levels, 3, 0);

MY_TEST2(test_tree, fanout_bits, 4, levels, 1, 0);
MY_TEST2(test_tree, fanout_bits, 4, levels, 3, 0);

MTF_END_UTEST_COLLECTION(test)
