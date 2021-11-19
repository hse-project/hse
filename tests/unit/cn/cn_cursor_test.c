/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * A note on the mocking concept.
 *
 * The struct nkv_tab is used to allow a table-driven approach to
 * both creating kvset data and verifying the returned data are correct.
 *
 * The kvsets are constructed manually, then inserted into the specific
 * locations in the cn tree.
 *
 * The dgen used by cn is obtained during cn_open by querying the cn tree.
 * However, this dgen will not match the dgen of the manually created kvsets,
 * and the cn_cursor will fail when dgens are out of order.  Thus the
 * mapi_inject is used to force cn to read the dgen of the last kvset created
 * within the test.  This is not intuitive.
 */

#include <mtf/framework.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>

#include <kvdb/kvdb_kvs.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_kvdb.h>
#include <hse_ikvdb/cursor.h>
#include <hse_ikvdb/kvdb_health.h>
#include <mpool/mpool.h>

#include <cn/cn_internal.h>
#include <cn/cn_tree_internal.h>
#include <cn/cndb_internal.h>
#include <cn/cn_tree.h>
#include <cn/cn_tree_create.h>
#include <cn/cn_tree_cursor.h>
#include <cn/cn_cursor.h>
#include <cn/kvset.h>

#include <mocks/mock_mpool.h>
#include <mocks/mock_kvset.h>

static struct kvs_rparams rp;
static struct kvdb_health health;
static struct cn_kvdb *cn_kvdb;

/* use a number that will never filter by seqno */
static u64 seqno = -4;

int
test_collection_setup(struct mtf_test_info *info)
{
    merr_t err;

    mock_mpool_set();
    mock_kvset_set();

    err = cn_kvdb_create(4, 4, &cn_kvdb);
    if (err)
        abort();

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    cn_kvdb_destroy(cn_kvdb);
    mock_mpool_unset();
    mock_kvset_unset();
    return 0;
}

int
pre(struct mtf_test_info *info)
{
    mock_mpool_set(); /* mdc mocks */
    mock_kvset_set(); /* neuter the tree */

    rp.cn_diag_mode = 1;

    mapi_inject(mapi_idx_cndb_cn_blob_get, 0);
    mapi_inject(mapi_idx_cndb_cn_blob_set, 0);
    mapi_inject(mapi_idx_kvset_pt_start, -1);
    mapi_inject_ptr(mapi_idx_ikvdb_get_mclass_policy, (void *)5);
    mapi_inject_ptr(mapi_idx_ikvdb_get_csched, NULL);
    mapi_inject(mapi_idx_ikvdb_read_only, false);

    return 0;
}

int
post(struct mtf_test_info *info)
{
    mock_kvset_unset();
    mock_mpool_unset();

    mapi_inject_clear();

    return 0;
}

/* Must be larger than sizeof(struct ikvdb_impl).
 */
const size_t dummy_ikvdb_sz = PAGE_SIZE * 8;

/* Create a dummy ikvdb object that will trip a segfault when accessed.
 */
void *
dummy_ikvdb_create(void)
{
    void *p;

    p = mmap(NULL, dummy_ikvdb_sz, PROT_NONE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED)
        abort();

    return p;
}

void
dummy_ikvdb_destroy(void *p)
{
    munmap(p, dummy_ikvdb_sz);
}

/* --------------------------------------------------
 * cursor verification by table of values
 */

#define ITV_KVSET(itv) ((struct kvset *)(((struct mock_kv_iterator *)(itv))->kvset))

#define ITV_KVSET_MOCK(itv) (((struct mock_kv_iterator *)(itv))->kvset)

/*
 * Use big-endian keys, as they form natural prefixes for short lengths.
 * For prefix length 3, keys 0-0x400 have 4 prefixes: 00 01 02 03.
 *
 * This is similar to the pattern used by putbin.
 */

#define ITV_INIT(itv, i, make) ASSERT_EQ(0, mock_make_kvi(&itv[i], i, &rp, &make[i]))

static u8 kbuf[HSE_KVS_KEY_LEN_MAX];

static void
cn_cursor_read_internal(struct mtf_test_info *lcl_ti,
                        struct cn_cursor * cur,
                        struct kvs_kvtuple *kvt,
                        bool *eof)
{
    struct kvs_cursor_element elem;
    uint klen;
    merr_t err;

    err = cn_cursor_read(cur, &elem, eof);
    ASSERT_EQ(err, 0);

    if (*eof)
        return;

    key_obj_copy(kbuf, sizeof(kbuf), &klen, &elem.kce_kobj);
    kvs_ktuple_init(&kvt->kvt_key, kbuf, klen);
    kvt->kvt_value = elem.kce_vt;
}

static void
verify(struct mtf_test_info *lcl_ti, struct cn_cursor *cur, struct nkv_tab *vtab, int vc, int keep)
{
    bool   eof;
    int    vi, nk;
    int    key, val;

    vi = 0;
    nk = 0;
    key = vc ? vtab[0].key1 : 0;
    val = vc ? vtab[0].val1 : 0;

    while (1) {
        struct kvs_kvtuple kvt = {0};
        const int *        ip;

        cn_cursor_read_internal(lcl_ti, cur, &kvt, &eof);
        if (eof)
            break;

        /* Ignore tombstones from cursor read.
         */
        if (HSE_CORE_IS_TOMB(kvt.kvt_value.vt_data))
            continue;

        /* validate reading correct keys and values */
        ip = kvt.kvt_key.kt_data;
        ASSERT_EQ(ntohl(*ip), key);
        ASSERT_NE(kvt.kvt_value.vt_data, NULL);
        ip = kvt.kvt_value.vt_data;
        ASSERT_EQ(*ip, val);

        ++key;
        ++val;

        if (++nk == vtab[vi].nkeys) {
            nk = 0;
            if (++vi < vc) {
                key = vtab[vi].key1;
                val = vtab[vi].val1;
            }
        }
    }
    ASSERT_EQ(eof, true);
    ASSERT_EQ(vi, vc);

    if (!keep)
        cn_cursor_destroy(cur);
}

static void
verify_cursor(
    struct mtf_test_info *lcl_ti,
    struct cn *           cn,
    void *                pfx,
    int                   pfx_len,
    struct nkv_tab *      vtab,
    int                   vc)
{
    struct cursor_summary sum;
    struct cn_cursor *    cur;
    merr_t                err;

    /* make seqno so large there is never any filtering */
    err = cn_cursor_create(cn, seqno, false, pfx, pfx_len, &sum, &cur);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cur, NULL);

    cn_cursor_prepare(cur);

    verify(lcl_ti, cur, vtab, vc, 0);
}

static void
verify_seek(
    struct mtf_test_info *lcl_ti,
    struct cn *           cn,
    void *                pfx,
    int                   pfx_len,
    void *                seek,
    int                   seeklen,
    struct nkv_tab *      vtab,
    int                   vc)
{
    struct cursor_summary sum;
    struct cn_cursor *    cur;
    merr_t                err;

    err = cn_cursor_create(cn, seqno, false, pfx, pfx_len, &sum, &cur);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cur, NULL);

    err = cn_cursor_seek(cur, seek, seeklen, 0);
    ASSERT_EQ(err, 0);

    verify(lcl_ti, cur, vtab, vc, 0);
}

static
void
verify_seek_eof(
    struct mtf_test_info *lcl_ti,
    struct cn            *cn,
    void                 *pfx,
    int                   pfx_len,
    void                 *seek,
    int                   seeklen,
    struct nkv_tab       *vtab,
    int                   vc)
{
    struct cursor_summary sum;
    struct cn_cursor *    cur;
    merr_t err;

    err = cn_cursor_create(cn, seqno, false, pfx, pfx_len, &sum, &cur);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cur, NULL);

    cn_cursor_prepare(cur);

    /* read through entire set */
    verify(lcl_ti, cur, vtab, vc, 1);

    /* verify asserted we hit eof - so now seek */
    err = cn_cursor_seek(cur, seek, seeklen, 0);
    ASSERT_EQ(err, 0);

    verify(lcl_ti, cur, vtab, vc, 0);
}

MTF_BEGIN_UTEST_COLLECTION_PRE(cn_cursor, test_collection_setup)

MTF_DEFINE_UTEST_PREPOST(cn_cursor, create_prefix, pre, post)
{
    struct cn *        cn;
    struct mpool *     ds = (void *)-1;
    struct cndb        cndb;
    struct cndb_cn     cndbcn = cndb_cn_initializer(3, 0, 0);
    struct kvdb_kvs    kk = { 0 };
    struct kvs_cparams cp = {};

    merr_t err;

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);
    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cn, NULL);

    verify_cursor(lcl_ti, cn, "prefix", 6, 0, 0);
    verify_cursor(lcl_ti, cn, 0, 0, 0, 0);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, create_noprefix, pre, post)
{
    struct cn *        cn;
    struct mpool *     ds = (void *)-1;
    merr_t             err;
    struct cndb        cndb;
    struct cndb_cn     cndbcn = cndb_cn_initializer(3, 0, 0);
    struct kvdb_kvs    kk = { 0 };
    struct kvs_cparams cp = {};

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cn, NULL);

    verify_cursor(lcl_ti, cn, 0, 0, 0, 0);
    verify_cursor(lcl_ti, cn, "prefix", 6, 0, 0);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, repeat_update, pre, post)
{
    struct cn *         cn;
    struct cn_tree *    tree;
    struct mock_kvset * mk;
    struct mpool *      ds = (void *)-1;
    struct kv_iterator *itv[1];
    struct cn_cursor     *cur;
    merr_t         err;
    struct cndb    cndb;
    struct cndb_cn cndbcn = cndb_cn_initializer(3, 0, 0);
    struct cursor_summary sum;
    struct kvdb_kvs    kk = { 0 };
    struct kvs_cparams cp = {};

    struct nkv_tab make[] = {
        { 0x400, 0, 0, VMX_S32, KVDATA_BE_KEY, 1 },
    };

    ITV_INIT(itv, 0, make);

    mk = ITV_KVSET_MOCK(itv[0]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[0]), 0, 0);
    ASSERT_EQ(err, 0);

    err = cn_cursor_create(cn, seqno, false, NULL, 0, &sum, &cur);
    ASSERT_EQ(err, 0);
    ASSERT_NE(cur, NULL);

    /*
     * Calling update after update in an EAGAIN scenario gives SIGBUS
     * for a duplicate free.  This is because cn_tree_cursor_destroy
     * will be called twice (multiple) times in a row.
     */

    cn_tree_cursor_destroy(cur);
    cn_tree_cursor_destroy(cur);
    cn_cursor_destroy(cur);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);

    for (int i = 0; i < NELEM(make); ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, root_1kvset, pre, post)
{
    struct cn *         cn;
    struct cn_tree *    tree;
    struct mock_kvset * mk;
    struct mpool *      ds = (void *)-1;
    struct kv_iterator *itv[1];

    merr_t             err;
    struct cndb        cndb;
    struct cndb_cn     cndbcn = cndb_cn_initializer(3, 0, 0);
    struct kvdb_kvs    kk = { 0 };
    struct kvs_cparams cp = {};

    struct nkv_tab make[] = {
        { 0x400, 0, 0, VMX_S32, KVDATA_BE_KEY, 1 },
    };

    unsigned char   pfx1[] = { 0, 0, 1 };
    unsigned char   pfx2[] = { 0, 0, 2 };
    unsigned char   pfx5[] = { 0, 0, 5 };

    struct nkv_tab  vtab[] = {
        { 0x100, 0x200, 0x200, VMX_S32, 0, 0 },
        { 0x100, 0x100, 0x100, VMX_S32, 0, 0 },
        /* none */
    };

    ITV_INIT(itv, 0, make);

    mk = ITV_KVSET_MOCK(itv[0]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[0]), 0, 0);
    ASSERT_EQ(err, 0);

    verify_cursor(lcl_ti, cn, pfx2, sizeof(pfx2), vtab, 1);
    verify_cursor(lcl_ti, cn, pfx1, sizeof(pfx2), vtab+1, 1);
    verify_cursor(lcl_ti, cn, pfx5, sizeof(pfx5), 0, 0);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);

    for (int i = 0; i < NELEM(make); ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, root_4kvsets, pre, post)
{
    struct cn *         cn;
    struct cn_tree *    tree;
    struct mock_kvset * mk;
    struct mpool *      ds = (void *)-1;
    struct kv_iterator *itv[4];
    merr_t              err;
    int                 i;
    struct cndb         cndb;
    struct cndb_cn      cndbcn = cndb_cn_initializer(3, 0, 0);
    struct kvs_cparams  cp = {};

    struct kvdb_kvs kk = { 0 };

    /*
     * create 4 kvsets in root,
     * verify with multiple prefixes and ranges
     */

    struct nkv_tab make[] = { { 0x400, 0, 0, VMX_S32, KVDATA_BE_KEY, 1 },
                              { 0x400, 0x100, 0x1100, VMX_S32, KVDATA_BE_KEY, 2 },
                              { 0x040, 0x080, -1, VMX_S32, KVDATA_BE_KEY, 3 }, /* tombs */
                              { 0x400, 0x200, 0x2200, VMX_S32, KVDATA_BE_KEY, 4 } };

    unsigned char pfx0[] = { 0, 0, 0 };
    unsigned char pfx1[] = { 0, 0, 1 };
    unsigned char pfx2[] = { 0, 0, 2 };
    unsigned char pfx9[] = { 0, 0, 9 };
    unsigned char all[]  = { 0, 0 };

    struct nkv_tab vtab[] = {
        { 0x080, 0, 0, VMX_S32, 0, 0 }, /* dgen 1 */
        /* tombstones from 0x80..0xc0      dgen 3 */
        { 0x040, 0x0c0, 0xc0, VMX_S32, 0, 0 },   /* dgen 1 */
        { 0x100, 0x100, 0x1100, VMX_S32, 0, 0 }, /* dgen 2 */
        { 0x100, 0x200, 0x2200, VMX_S32, 0, 0 }, /* dgen 4 */
        { 0x300, 0x300, 0x2300, VMX_S32, 0, 0 }  /* dgen 4 */
    };

    ITV_INIT(itv, 0, make);
    ITV_INIT(itv, 1, make);
    ITV_INIT(itv, 2, make);
    ITV_INIT(itv, 3, make);

    mk = ITV_KVSET_MOCK(itv[3]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);
    mapi_inject_ptr(mapi_idx_ikvdb_get_csched, NULL);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    /*
     * install mock_kvset and mock_kv_iterator seeds into the tree
     */
    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    for (i = 0; i < NELEM(make); ++i) {
        err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[i]), 0, 0);
        ASSERT_EQ(err, 0);
    }

    /*
     * and validate we get what we expect
     */
    verify_cursor(lcl_ti, cn, pfx0, sizeof(pfx0), vtab, 2);
    verify_cursor(lcl_ti, cn, pfx1, sizeof(pfx1), vtab+2, 1);
    verify_cursor(lcl_ti, cn, pfx2, sizeof(pfx2), vtab+3, 1);
    verify_cursor(lcl_ti, cn, pfx9, sizeof(pfx9), 0, 0);
    verify_cursor(lcl_ti, cn, all, sizeof(all), vtab, 5);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    for (i = 0; i < NELEM(make); ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, prefix_tree, pre, post)
{
    struct cn *         cn;
    struct cn_tree *    tree;
    struct mock_kvset * mk;
    struct mpool *      ds = (void *)-1;
    struct kv_iterator *itv[8];
    merr_t              err;
    int                 i;

    struct cndb        cndb;
    struct cndb_cn     cndbcn = cndb_cn_initializer(2, 0, 0);
    struct kvs_cparams cp = {};

    struct kvdb_kvs kk = { 0 };

    /*
     * create a tree with fanout 4, populate root, level 1,
     * and two nodes of level 2; verify we still get only
     * those keys desired.
     *
     * The nodes of level 2 were identified using the prefixes
     * below, and using pscan's -n4 -p options to determine
     * which fingers should hold which keys.
     *
     * In particular, a prefix of
     *  0,0,1 resides in root / 1,1 / 2,6
     *  0,0,2 resides in root / 1,2 / 2,9
     *
     * Important: kvsets created first must be located deepest
     * in the tree.
     *
     * Moreover, the dgens must be seen in a cursor scan in
     * order from highest to lowest.
     */

    struct nkv_tab make[] = {
        { 0x80, 0x200, 0x2900, VMX_S32, KVDATA_BE_KEY, 1 }, /* loc 2,9 */
        { 0x80, 0x100, 0x2600, VMX_S32, KVDATA_BE_KEY, 1 }, /* loc 2,6 */

        { 0x40, 0x760, 0x1300, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,3 */
        { 0x40, 0x260, 0x1200, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,2 */
        { 0x40, 0x160, 0x1100, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,1 */
        { 0x40, 0x000, 0x1000, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,0 */
        { 0x20, 0x900, 0x0000, VMX_S32, KVDATA_BE_KEY, 3 }, /* loc 0,0 */
        { 0x20, 0x190, 0x0000, VMX_S32, KVDATA_BE_KEY, 4 }, /* loc 0,0 */
    };

    unsigned char pfx1[] = { 0, 0, 1 };
    unsigned char pfx2[] = { 0, 0, 2 };
    unsigned char all[]  = { 0, 0 };

    struct nkv_tab vtab[] = {
        { 0x60,  0x200, 0x2900, VMX_S32, 0, 0 },/* pfx2, loc 2,9 */
        { 0x40,  0x260, 0x1200, VMX_S32, 0, 0 },/* pfx2, loc 1,2 */

        { 0x60,  0x100, 0x2600, VMX_S32, 0, 0 },/* pfx1, loc 2,6 */
        { 0x30,  0x160, 0x1100, VMX_S32, 0, 0 },/* pfx1, loc 1,1 */
        { 0x20,  0x190, 0x0000, VMX_S32, 0, 0 },/* pfx1, loc 0,0 */

        /* full scan sees this */
        { 0x40,  0x000, 0x1000, VMX_S32, 0, 0 },/* dgen 3, loc 1,0 */
        { 0x60,  0x100, 0x2600, VMX_S32, 0, 0 },/* dgen 1, loc 2,6 */
        { 0x30,  0x160, 0x1100, VMX_S32, 0, 0 },/* dgen 4, loc 1,1 */
        { 0x20,  0x190, 0x0000, VMX_S32, 0, 0 },/* dgen 8, loc 0,0 */
        { 0x60,  0x200, 0x2900, VMX_S32, 0, 0 },/* dgen 2, loc 2,9 */
        { 0x40,  0x260, 0x1200, VMX_S32, 0, 0 },/* dgen 5, loc 1,2 */
        { 0x40,  0x760, 0x1300, VMX_S32, 0, 0 },/* dgen 6, loc 1,3 */
        { 0x20,  0x900, 0x0000, VMX_S32, 0, 0 },/* dgen 7, loc 0,0 */
    };

    struct locmap {
        int lvl;
        int off;
        int itv;
    } locmap[] = {
        /* order is important here: dgen must run big to small */
        { 0, 0, 6 }, { 0, 0, 7 },

        { 1, 3, 2 }, { 1, 2, 3 }, { 1, 1, 4 }, { 1, 0, 5 },

        { 2, 9, 0 }, { 2, 6, 1 },
    };

    ITV_INIT(itv, 0, make);
    ITV_INIT(itv, 1, make);
    ITV_INIT(itv, 2, make);
    ITV_INIT(itv, 3, make);
    ITV_INIT(itv, 4, make);
    ITV_INIT(itv, 5, make);
    ITV_INIT(itv, 6, make);
    ITV_INIT(itv, 7, make);

    mk = ITV_KVSET_MOCK(itv[7]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);
    mapi_inject_ptr(mapi_idx_ikvdb_get_csched, NULL);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 2;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    /*
     * install mock_kvset and mock_kv_iterator seeds into the tree
     */
    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    for (i = 0; i < NELEM(locmap); ++i) {
        struct kvset *kvset = ITV_KVSET(itv[locmap[i].itv]);

        err = cn_tree_insert_kvset(tree, kvset, locmap[i].lvl, locmap[i].off);
        ASSERT_EQ(err, 0);
    }

    /*
     * and validate we get what we expect
     */
    verify_cursor(lcl_ti, cn, pfx2, sizeof(pfx2), vtab, 2);
    verify_cursor(lcl_ti, cn, pfx1, sizeof(pfx1), vtab+2, 3);
    verify_cursor(lcl_ti, cn, all,  sizeof(all),  vtab+5, 8);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    for (i = 0; i < NELEM(make); ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, cursor_seek, pre, post)
{
    struct cn *         cn;
    struct cn_tree *    tree;
    struct mock_kvset * mk;
    struct mpool *      ds = (void *)-1;
    struct kv_iterator *itv[8];
    merr_t              err;
    int                 i;

    struct cndb    cndb;
    struct cndb_cn cndbcn = cndb_cn_initializer(2, 0, 0);

    struct kvdb_kvs kk = { 0 };

    struct kvs_cparams cp = {};

    /*
     * create a tree with fanout 4, populate root, level 1,
     * and two nodes of level 2; verify we still get only
     * those keys desired.
     *
     * The nodes of level 2 were identified using the prefixes
     * below, and using pscan's -n4 -p options to determine
     * which fingers should hold which keys.
     *
     * In particular, a prefix of
     *  0,0,1 resides in root / 1,1 / 2,6
     *  0,0,2 resides in root / 1,2 / 2,9
     *
     * Important: kvsets created first must be located deepest
     * in the tree.
     *
     * Moreover, the dgens must be seen in a cursor scan in
     * order from highest to lowest.
     */

    struct nkv_tab make[] = {
        { 0x80, 0x200, 0x2900, VMX_S32, KVDATA_BE_KEY, 1 }, /* loc 2,9 */
        { 0x80, 0x100, 0x2600, VMX_S32, KVDATA_BE_KEY, 1 }, /* loc 2,6 */

        { 0x40, 0x760, 0x1300, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,3 */
        { 0x40, 0x260, 0x1200, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,2 */
        { 0x40, 0x160, 0x1100, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,1 */
        { 0x40, 0x000, 0x1000, VMX_S32, KVDATA_BE_KEY, 2 }, /* loc 1,0 */

        { 0x20, 0x900, 0x0000, VMX_S32, KVDATA_BE_KEY, 3 }, /* loc 0,0 */
        { 0x20, 0x190, 0x0000, VMX_S32, KVDATA_BE_KEY, 4 }, /* loc 0,0 */
    };

    unsigned char pfx1[] = { 0, 0, 1 };

    unsigned char seek0[] = { 0, 0, 0, 0 }; /* before */
    unsigned char seek1[] = { 0, 0, 1, 0 };     /* first */
    unsigned char seek2[] = { 0, 0, 1, 0x80 };  /* middle */
    unsigned char seek3[] = { 0, 0, 2, 0 };     /* past */

    struct nkv_tab vtab[] = {
        /* seek0, seek1 */
        { 0x60,  0x100, 0x2600,
          VMX_S32, 0, 0 },      /* pfx1, loc 2,6 */
        { 0x30,  0x160, 0x1100,
          VMX_S32, 0, 0 },      /* pfx1, loc 1,1 */
        { 0x20,  0x190, 0x0000,
          VMX_S32, 0, 0 },      /* pfx1, loc 0,0 */

        /* seek2 */
        { 0x10,  0x180, 0x1120,
          VMX_S32, 0, 0 },      /* pfx1, loc 1,1 */
        { 0x20,  0x190, 0x0000,
          VMX_S32, 0, 0 },      /* pfx1, loc 0,0 */

        /* seek3 */
        /* eof */
    };

    struct locmap {
        int lvl;
        int off;
        int itv;
    } locmap[] = {
        /* order is important here: dgen must run big to small */
        { 0, 0, 6 }, { 0, 0, 7 },

        { 1, 3, 2 }, { 1, 2, 3 }, { 1, 1, 4 }, { 1, 0, 5 },

        { 2, 9, 0 }, { 2, 6, 1 },
    };

    ITV_INIT(itv, 0, make);
    ITV_INIT(itv, 1, make);
    ITV_INIT(itv, 2, make);
    ITV_INIT(itv, 3, make);
    ITV_INIT(itv, 4, make);
    ITV_INIT(itv, 5, make);
    ITV_INIT(itv, 6, make);
    ITV_INIT(itv, 7, make);

    mk = ITV_KVSET_MOCK(itv[7]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 2;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    /*
     * install mock_kvset and mock_kv_iterator seeds into the tree
     */
    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    /* test seek on empty tree */
    verify_seek(lcl_ti, cn, 0, 0, seek0, sizeof(seek0), 0, 0);

    for (i = 0; i < NELEM(locmap); ++i) {
        struct kvset *kvset = ITV_KVSET(itv[locmap[i].itv]);

        err = cn_tree_insert_kvset(tree, kvset, locmap[i].lvl, locmap[i].off);
        ASSERT_EQ(err, 0);
    }

    /*
     * and validate we get what we expect
     */
#define VERIFY(pfx, seek, vtab, vc) \
    verify_seek(lcl_ti, cn, pfx, sizeof(pfx), seek, sizeof(seek), vtab, vc)

    VERIFY(pfx1, seek0, vtab,   3);
    VERIFY(pfx1, seek1, vtab,   3);
    VERIFY(pfx1, seek2, vtab+3, 2);
    VERIFY(pfx1, seek3, 0,      0);
#undef VERIFY

    verify_seek_eof(lcl_ti, cn, pfx1, sizeof(pfx1),
            seek0, sizeof(seek0), vtab, 3);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    for (i = 0; i < NELEM(make); ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);
}

void
_kvset_maxkey(struct kvset *ks, const void **maxkey, u16 *maxklen)
{
    static char max[sizeof(u32)];
    u32 *       p = (void *)max;

    *p = htobe32(10);
    *maxkey = p;
    *maxklen = sizeof(u32);
}

void
_kvset_minkey(struct kvset *ks, const void **minkey, u16 *minklen)
{
    static char min[sizeof(u32)];
    u32 *       p = (void *)min;

    *p = htobe32(0);
    *minkey = p;
    *minklen = sizeof(u32);
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, capped_update, pre, post)
{
    struct cn *           cn;
    struct cn_tree *      tree;
    struct mock_kvset *   mk;
    struct mpool *        ds = (void *)-1;
    struct kv_iterator *  itv[5];
    struct cn_cursor *    cur;
    merr_t                err;
    struct cndb           cndb;
    struct cndb_cn        cndbcn = cndb_cn_initializer(3, 0, 0);
    struct cursor_summary sum;
    struct kvdb_kvs       kk = { 0 };
    struct kvs_cparams    cp = {};
    int                   i;
    const int             initial_kvset_cnt = 4;

    struct nkv_tab make[] = {
        { 1024, 1024 * 0, 0, VMX_S32, KVDATA_BE_KEY, 1 },
        { 1024, 1024 * 1, 0, VMX_S32, KVDATA_BE_KEY, 2 },
        { 1024, 1024 * 2, 0, VMX_S32, KVDATA_BE_KEY, 3 },
        { 1024, 1024 * 3, 0, VMX_S32, KVDATA_BE_KEY, 4 },
        { 1024, 1024 * 4, 0, VMX_S32, KVDATA_BE_KEY, 5 },
    };

    ITV_INIT(itv, 0, make);
    ITV_INIT(itv, 1, make);
    ITV_INIT(itv, 2, make);
    ITV_INIT(itv, 3, make);
    ITV_INIT(itv, 4, make);

    mk = ITV_KVSET_MOCK(itv[initial_kvset_cnt - 1]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;
    kk.kk_cparams->kvs_ext01 = 1;
    kk.kk_flags = CN_CFLAG_CAPPED;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    for (i = 0; i < initial_kvset_cnt; ++i) {
        err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[i]), 0, 0);
        ASSERT_EQ(err, 0);
    }

    /* Test 1: capped cursor update test */
    err = cn_cursor_create(cn, seqno, false, NULL, 0, &sum, &cur);
    ASSERT_EQ(err, 0);

    for (; i < NELEM(make); ++i) {
        err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[i]), 0, 0);
        ASSERT_EQ(err, 0);
    }

    bool updated = false;

    tree->ct_root->tn_ns.ns_kst.kst_kvsets = NELEM(make);
    atomic_set(&cn->cn_ingest_dgen, 5);
    err = cn_cursor_update(cur, seqno, &updated);
    ASSERT_EQ(0, err);
    ASSERT_EQ(true, updated);

    int count;

    err = cn_cursor_seek(cur, 0, 0, 0);
    ASSERT_EQ(0, err);

    for (count = 0;;) {
        struct kvs_kvtuple kvt;
        bool               eof;

        cn_cursor_read_internal(lcl_ti, cur, &kvt, &eof);
        if (eof)
            break;

        ++count;
    }
    for (i = 0; i < NELEM(make); ++i) {
        ASSERT_GE(count, make[i].nkeys);
        count -= make[i].nkeys;
    }
    ASSERT_EQ(count, 0);

    /* Test2: limited cursor seek test */
    char u_bound[sizeof(u32)];
    u32 *p = (void *)u_bound;

    *p = htobe32(10); /* read up to and including key '10' */

    struct kc_filter filter = {
        .kcf_maxkey = p,
        .kcf_maxklen = sizeof(u32),
    };

    MOCK_SET(kvset, _kvset_maxkey);
    MOCK_SET(kvset, _kvset_minkey);

    err = cn_cursor_seek(cur, 0, 0, &filter);
    ASSERT_EQ(0, err);

    for (count = 0;;) {
        struct kvs_kvtuple kvt;
        bool               eof;

        cn_cursor_read_internal(lcl_ti, cur, &kvt, &eof);
        if (eof)
            break;

        ++count;
    }
    ASSERT_EQ(11, count); /* Expect keys from '0' to '10', i.e. 11 keys */

    cn_cursor_destroy(cur);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);

    for (i = 0; i < NELEM(make); ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }

    MOCK_UNSET(kvset, _kvset_maxkey);
    MOCK_UNSET(kvset, _kvset_minkey);
}

MTF_DEFINE_UTEST_PREPOST(cn_cursor, capped_update_errors, pre, post)
{
    struct cn *           cn;
    struct cn_tree *      tree;
    struct mock_kvset *   mk;
    struct mpool *        ds = (void *)-1;
    struct kv_iterator *  itv[5];
    struct cn_cursor *    cur;
    merr_t                err;
    struct cndb           cndb;
    struct cndb_cn        cndbcn = cndb_cn_initializer(3, 0, 0);
    struct cursor_summary sum;
    struct kvdb_kvs       kk = { 0 };
    struct kvs_cparams    cp = {};
    int                   i;
    const int             initial_kvset_cnt = 2;

    struct nkv_tab make[] = {
        { 1024, 1024 * 0, 0, VMX_S32, KVDATA_BE_KEY, 1 },
        { 1024, 1024 * 1, 0, VMX_S32, KVDATA_BE_KEY, 2 },
        { 1024, 1024 * 2, 0, VMX_S32, KVDATA_BE_KEY, 3 },
        { 1024, 1024 * 3, 0, VMX_S32, KVDATA_BE_KEY, 4 },
        { 1024, 1024 * 4, 0, VMX_S32, KVDATA_BE_KEY, 5 },
    };

    ITV_INIT(itv, 0, make);
    ITV_INIT(itv, 1, make);
    ITV_INIT(itv, 2, make);
    ITV_INIT(itv, 3, make);
    ITV_INIT(itv, 4, make);

    mk = ITV_KVSET_MOCK(itv[initial_kvset_cnt - 1]);
    mapi_inject(mapi_idx_cn_tree_initial_dgen, mk->dgen);

    err = cndb_init(&cndb, ds, true, 0, CNDB_ENTRIES, 0, 0, &health, 0);
    ASSERT_EQ(err, 0);

    cndb.cndb_cnc = 1;
    cndb.cndb_cnv[0] = &cndbcn;
    ASSERT_NE(cndb.cndb_workv, NULL);
    ASSERT_NE(cndb.cndb_keepv, NULL);
    ASSERT_NE(cndb.cndb_tagv, NULL);

    kk.kk_parent = dummy_ikvdb_create();
    kk.kk_cparams = &cp;
    kk.kk_cparams->fanout = 1 << 3;
    kk.kk_cparams->kvs_ext01 = 1;
    kk.kk_flags = CN_CFLAG_CAPPED;

    err = cn_open(cn_kvdb, ds, &kk, &cndb, 0, &rp, "mp", "kvs", &health, 0, &cn);
    ASSERT_EQ(err, 0);

    tree = cn_get_tree(cn);
    ASSERT_NE(tree, NULL);

    for (i = 0; i < initial_kvset_cnt; ++i) {
        err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[i]), 0, 0);
        ASSERT_EQ(err, 0);
    }

    err = cn_cursor_create(cn, seqno, false, NULL, 0, &sum, &cur);
    ASSERT_EQ(err, 0);

    for (; i < NELEM(make); ++i) {
        err = cn_tree_insert_kvset(tree, ITV_KVSET(itv[i]), 0, 0);
        ASSERT_EQ(0, err);
    }

    bool updated = false;

    tree->ct_root->tn_ns.ns_kst.kst_kvsets = NELEM(make);
    atomic_set(&cn->cn_ingest_dgen, 5);
    mapi_inject(mapi_idx_kvset_iter_create, merr(EBUG));
    err = cn_cursor_update(cur, seqno, &updated);
    ASSERT_EQ(EBUG, merr_errno(err));
    ASSERT_EQ(true, updated);

    cn_cursor_destroy(cur);

    err = cn_close(cn);
    ASSERT_EQ(err, 0);

    dummy_ikvdb_destroy(kk.kk_parent);
    free(cndb.cndb_workv);
    free(cndb.cndb_keepv);
    free(cndb.cndb_tagv);
    free(cndb.cndb_cbuf);

    for (i = 0; i < 2; ++i) {
        struct mock_kv_iterator *iter = itv[i]->kvi_context;
        struct kvdata *          d = iter->kvset->iter_data;

        free(d);
        kvset_iter_release(itv[i]);
    }

    for (; i < NELEM(make); ++i)
        kvset_iter_release(itv[i]);

    MOCK_UNSET(kvset, _kvset_maxkey);
    MOCK_UNSET(kvset, _kvset_minkey);
}

MTF_END_UTEST_COLLECTION(cn_cursor)
