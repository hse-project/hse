/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/seqno.h>

#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c1.h>
#include <hse_ikvdb/c0sk.h>
#include <hse_ikvdb/c0skm.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/kvb_builder.h>
#include <hse_ikvdb/kvdb_health.h>
#include <hse_ikvdb/kvdb_rparams.h>

#include "../../c0/test/cn_mock.h"
#include <hse_test_support/key_generation.h>
#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/csched.h>
#include <hse_ikvdb/c1_perfc.h>
#include <hse_test_support/random_buffer.h>

#include "../../c0/c0sk_internal.h"
#include "../../c0/c0_cursor.h"
#include "../../c0/c0_kvmsm.h"
#include "../../c0/c0_kvmsm_internal.h"
#include "../../c1/c1_private.h"
#include "../../c1/c1_io_internal.h"
#include "../../c1/c1_journal_internal.h"
#include "../../c1/c1_log.h"
#include "../../c1/c1_tree_utils.h"
#include "../../c1/c1_omf_internal.h"
#include "../../kvdb/test/mock_c1.h"
#include "mock_mpool.h"

#include <assert.h>
#include <stdlib.h>
#include <unistd.h>

static struct kvdb_health mock_health;
struct csched *           csched;
struct kvdb_rparams       kvdb_rp;

static int
test_collection_setup(struct mtf_test_info *info)
{
    fail_nth_alloc_test_pre(info);
    kvdb_rp = kvdb_rparams_defaults();
    csched_create(csched_policy_noop, NULL, &kvdb_rp, "mp_name", &mock_health, &csched);
    return 0;
}

static merr_t
_kvset_builder_create(
    struct kvset_builder **builder_out,
    struct cn *            cn,
    struct perfc_set *     pc,
    u64                    vgroup,
    uint                   flags)
{
    *builder_out = (struct kvset_builder *)1111;
    return 0;
}

void
_kvset_builder_set_agegroup(struct kvset_builder *bldr, enum hse_mclass_policy_age age)
{
}

struct mock_kvdb {
    struct c0sk *ikdb_c0sk;
};

void
_ikvdb_get_c0sk(struct ikvdb *kvdb, struct c0sk **out)
{
    struct mock_kvdb *mkvdb = (struct mock_kvdb *)kvdb;

    *out = mkvdb->ikdb_c0sk;
}

static void
mocks_unset(void)
{
    mapi_inject_clear();
}

static void
mocks_set(struct mtf_test_info *info)
{
    /* Allow repeated test_collection_setup() w/o intervening unset() */
    mocks_unset();
    mock_c0skm_unset();
    mock_c1_unset();

    MOCK_SET(ikvdb, _ikvdb_get_c0sk);
    MOCK_SET(kvset_builder, _kvset_builder_create);
    MOCK_SET(kvset_builder, _kvset_builder_set_agegroup);

    mapi_inject(mapi_idx_kvset_builder_get_mblocks, 0);
    mapi_inject(mapi_idx_kvset_builder_add_key, 0);
    mapi_inject(mapi_idx_kvset_builder_add_val, 0);
    mapi_inject(mapi_idx_kvset_builder_add_nonval, 0);
    mapi_inject(mapi_idx_kvset_builder_add_vref, 0);
    mapi_inject(mapi_idx_kvset_builder_destroy, 0);
    mapi_inject(mapi_idx_kvset_mblocks_destroy, 0);
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    /*
     * WARNING: If mocks_unset is called with data in c0 on a workqueue,
     * the code will segv since the real kvset_builder_add_val is called.
     *
     * mocks_unset();
     */
    return 0;
}

int
no_fail_pre(struct mtf_test_info *info)
{
    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = -1;

    mocks_set(info);

    kvdb_health_clear(&mock_health, KVDB_HEALTH_FLAG_NOMEM);

    return 0;
}

int
no_fail_post(struct mtf_test_info *info)
{
    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = -1;
    MOCK_UNSET(c0sk_internal, _c0sk_release_multiset);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(c1_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST_PREPOST(c1_test, basic, no_fail_pre, no_fail_post)
{
    merr_t              err;
    struct kvdb_rparams kvdb_rp;
    struct mock_kvdb    mkvdb;
    atomic64_t          seqno;
    struct c1 *         c1;

    kvdb_rp = kvdb_rparams_defaults();

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    c1 = c1_create(NULL);
    ASSERT_EQ(NULL, c1);

    c1 = c1_create("mp");
    ASSERT_NE(NULL, c1);

    /* [HSE_REVISIT These map injections should work but don't, so for
     * now we rely ikvdb_c1_replay_del() and ikvdb_c1_replay_del()
     * to quietly fail because ikvdb is NULL.
     */
    err = c1_replay_on_ikvdb(c1, NULL, 0, 0, NULL, NULL, true);
    ASSERT_EQ(0, err);

    err = c1_replay_on_ikvdb(c1, NULL, 0, 0, NULL, NULL, false);
    ASSERT_EQ(0, err);

    c1_destroy(c1);
    c1 = NULL;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    c0skm_close(mkvdb.ikdb_c0sk);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    err = c0sk_close(NULL);
    ASSERT_NE(0, err);

    /* c1 perfc init/fini test */
    c1_perfc_fini();

    mapi_inject(mapi_idx_perfc_ivl_create, merr(EINVAL));
    c1_perfc_init();
    c1_perfc_fini();
    mapi_inject_unset(mapi_idx_perfc_ivl_create);

    c1_perfc_init();
    c1_perfc_fini();
}

MTF_DEFINE_UTEST_PREPOST(c1_test, basic2, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;
    atomic64_t          seqno;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_free(NULL, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();
    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0sk_close(mkvdb.ikdb_c0sk);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, basic3, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;
    atomic64_t          seqno;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_free(NULL, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();
    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0sk_close(mkvdb.ikdb_c0sk);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, basic4, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;
    int                 rc;
    struct c1_kvb       kvb1;
    struct c1_kvb       kvb2;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    mapi_inject_once(mapi_idx_c1_tree_get_desc, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_tree_get_desc);

    mapi_inject_once(mapi_idx_malloc, 4, 0);
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    kvb1.c1kvb_mutation = 2;
    kvb2.c1kvb_mutation = 1;
    rc = c1_tree_kvb_cmp(&kvb1, &kvb2);
    ASSERT_EQ(1, rc);

    kvb1.c1kvb_mutation = 1;
    kvb2.c1kvb_mutation = 2;
    rc = c1_tree_kvb_cmp(&kvb1, &kvb2);
    ASSERT_EQ(-1, rc);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    err = c1_free(NULL, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0skm_close(mkvdb.ikdb_c0sk);

    c0sk_close(mkvdb.ikdb_c0sk);

    c1_unmock_mpool();
}

MTF_DEFINE_UTEST_PREPOST(c1_test, c1_alloc_test, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;
    atomic64_t          seqno;
    int                 i;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
        mapi_inject_unset(mapi_idx_malloc);
    }

#if 0
    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_mpool_mdc_alloc, i, merr(ev(EIO)));
        mapi_inject_once(mapi_idx_mpool_mlog_alloc, i, merr(ev(EIO)));
        err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
        mapi_inject_unset(mapi_idx_mpool_mdc_alloc);
        mapi_inject_unset(mapi_idx_mpool_mlog_alloc);
    }

    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_mpool_mdc_append, i, merr(ev(EIO)));
        err  = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
        mapi_inject_unset(mapi_idx_mpool_mdc_append);
    }
#endif

    c1_unmock_mpool();

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, c1_make_test, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;
    atomic64_t          seqno;
    int                 i;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();
    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
        mapi_inject_unset(mapi_idx_malloc);
    }

#if 0
    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_mpool_mdc_open, i, merr(ev(EIO)));
        mapi_inject_once(mapi_idx_mpool_mlog_alloc, i, merr(ev(EIO)));
        err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
        mapi_inject_unset(mapi_idx_mpool_mdc_open);
        mapi_inject_unset(mapi_idx_mpool_mlog_alloc);
    }

    for (i = 1; i < 5; i++) {
        mapi_inject_once(mapi_idx_mpool_mdc_close, i, merr(ev(EIO)));
        mapi_inject_once(mapi_idx_mpool_mdc_append, i, merr(ev(EIO)));
        err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
        mapi_inject_unset(mapi_idx_mpool_mdc_close);
        mapi_inject_unset(mapi_idx_mpool_mdc_append);
    }
#endif

    err = c1_free(NULL, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, basic5, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_replay_add_info(c1, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    err = c1_replay_add_desc(c1, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    err = c1_replay_add_reset(c1, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    err = c1_replay_add_complete(c1, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject(mapi_idx_c1_journal_replay, merr(ENOMEM));
    err = c1_replay(c1);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_c1_journal_replay);

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0sk_close(mkvdb.ikdb_c0sk);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();
}

MTF_DEFINE_UTEST_PREPOST(c1_test, basic6, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    merr_t              err;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    mapi_inject_once(mapi_idx_c1_journal_compact_begin, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_journal_compact_begin);

    mapi_inject_once(mapi_idx_c1_journal_format, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_journal_format);

    mapi_inject_once(mapi_idx_c1_compact_reset_trees, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_compact_reset_trees);

    mapi_inject_once(mapi_idx_c1_compact_clean_trees, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_compact_clean_trees);

    mapi_inject_once(mapi_idx_c1_compact_inuse_trees, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_compact_inuse_trees);

    mapi_inject_once(mapi_idx_c1_compact_new_trees, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_compact_new_trees);

    mapi_inject_once(mapi_idx_c1_journal_compact_end, 1, merr(EINVAL));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_c1_journal_compact_end);

    /* [HSE_REVISIT] Seems like c1_open() should succeed at this point,
     * but doesn't, need to understand why we hit this assert:
     *
     * c1_tree.c:269: c1_tree_alloc_impl: Assertion `logsize != 0' failed.
     *
    err = c1_open(NULL, false, c1_oid1, c1_oid2, "mock_mp",
              &kvdb_rp, NULL, &c1);
    ASSERT_EQ(0, err);

    * [HSE_REVISIT] c0_close() also fails:
    * c1.c:300: c1_close: Assertion `c1' failed.
    *
    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    c0sk_close(mkvdb.ikdb_c0sk);

    err = c1_close(c1);
    ASSERT_EQ(0, err);
    */

    c0_close(test_c0);

    c0sk_close(mkvdb.ikdb_c0sk);

    destroy_mock_cn(mock_cn);

    c1_unmock_mpool();
}

MTF_DEFINE_UTEST_PREPOST(c1_test, ingest, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    struct kvs_ktuple   kt = { 0 };
    merr_t              err;
    uintptr_t           seqnoref;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    kt.kt_len = 3;
    kt.kt_data = "foo";
    seqnoref = HSE_ORDNL_TO_SQNREF(0);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0sk_close(mkvdb.ikdb_c0sk);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();
}

MTF_DEFINE_UTEST_PREPOST(c1_test, ingest2, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams      kvdb_rp;
    struct kvs_rparams       kvs_rp;
    struct kvb_builder_iter *iter;
    struct c0 *              test_c0;
    struct kvs_ktuple        kt;
    struct kvs_vtuple        vt;
    struct c1_tree *         tree;
    struct c1_kvinfo         cki = {};
    merr_t                   err;
    uintptr_t                seqnoref;
    struct mock_kvdb         mkvdb;
    struct cn *              mock_cn;
    atomic64_t               seqno;
    struct c1 *              c1;
    struct kvdb_cparams      kvdb_cp;
    u64                      c1_oid1;
    u64                      c1_oid2;
    int                      i;
    int                      mclass;
    bool                     repeat;

    struct c0_kvmultiset *kvms;
    uintptr_t             iseqno;

    repeat = true;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

again:
    memset(&kt, 0, sizeof(kt));
    atomic64_set(&seqno, 0);
    test_c0 = NULL;
    mclass = 0;
    c1 = NULL;

    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    kt.kt_len = 3;
    kt.kt_data = "foo";
    vt.vt_len = 3;
    vt.vt_data = "foo";

    seqnoref = HSE_ORDNL_TO_SQNREF(0);

    for (i = 0; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c0_put(test_c0, &kt, &vt, seqnoref);
        if (!err)
            c0_sync(test_c0);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 0; i < 10; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c0_put(test_c0, &kt, &vt, seqnoref);
        if (!err)
            c0_sync(test_c0);
        mapi_inject_unset(mapi_idx_malloc);
    }

    for (i = 0; i < 10; i++) {
        err = c0_put(test_c0, &kt, &vt, seqnoref);
        ASSERT_EQ(0, err);
    }
    c0_sync(test_c0);

    mapi_inject(mapi_idx_c0kvms_is_ingested, true);
    err = c0kvms_create(7, HSE_C0_CHEAP_SZ_MAX, 0, 0, true, &kvms);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, kvms);

    for (i = 0; i < 10; ++i) {
        struct kvs_ktuple kt;
        struct kvs_vtuple vt;
        struct c0_kvset * p;
        u64               key, val;

        p = c0kvms_get_hashed_c0kvset(kvms, i);
        ASSERT_NE(NULL, p);

        key = i;
        val = i;

        kvs_ktuple_init(&kt, &key, sizeof(key));
        kvs_vtuple_init(&vt, &val, sizeof(val));
        iseqno = HSE_ORDNL_TO_SQNREF(0);

        err = c0kvs_put(p, 0, &kt, &vt, iseqno);
        ASSERT_EQ(0, err);
    }

    c0kvms_putref(kvms);
    mapi_inject_unset(mapi_idx_c0kvms_is_ingested);

    cki.ck_kvsz = 128;
    err = c1_issue_iter(c1, NULL, 0, &cki, C1_INGEST_SYNC);
    ASSERT_EQ(0, err);

    err = c1_issue_sync(c1, C1_INGEST_SYNC, false);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = kvb_builder_iter_alloc(1, 1, 0, 2, NULL, &iter);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    kvb_builder_iter_destroy(NULL, NULL);
    kvb_builder_iter_put(NULL);

    err = c1_issue_iter(c1, NULL, 0, &cki, C1_INGEST_SYNC);
    ASSERT_EQ(0, err);

    cki.ck_kvsz = 1024;
    mapi_inject(mapi_idx_c1_tree_reserve_space_txn, merr(ENOSPC));
    err = c1_io_txn_begin(c1, 5, &cki, false);
    ASSERT_EQ(ENOSPC, merr_errno(err));
    mapi_inject_unset(mapi_idx_c1_tree_reserve_space_txn);

    mapi_inject(mapi_idx_c1_tree_reserve_space, merr(ENOSPC));
    err = c1_io_txn_begin(c1, 5, &cki, false);
    ASSERT_EQ(ENOSPC, merr_errno(err));
    mapi_inject_unset(mapi_idx_c1_tree_reserve_space);

    cki.ck_kvsz = 128;
    mapi_inject(mapi_idx_malloc, 0);
    err = c1_io_txn_begin(c1, 0, &cki, C1_INGEST_SYNC);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    err = c1_io_txn_commit(c1, 0, 128, C1_INGEST_SYNC);
    ASSERT_EQ(ENOMEM, merr_errno(err));

    err = c1_io_txn_abort(c1, 0);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 2, 0);
    err = c1_io_txn_begin(c1, 0, &cki, C1_INGEST_SYNC);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 2, 0);
    err = c1_io_txn_commit(c1, 0, 128, C1_INGEST_SYNC);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 2, 0);
    err = c1_io_txn_abort(c1, 0);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 1, 0);
    err = c1_io_create(c1, 50, "mock_mp", 4);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 2, 0);
    err = c1_io_create(c1, 50, "mock_mp", 4);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 3, 0);
    err = c1_io_create(c1, 50, "mock_mp", 4);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    err = c1_tree_alloc(NULL, 12, 1, 5, 6, &mclass, 4096, 4, 4096, &tree);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_tree_open(tree, true);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_tree_alloc(NULL, 12, 1, 5, 6, &mclass, 4096, 4, 4096, &tree);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject_once(mapi_idx_malloc, 2, 0);
    err = c1_tree_alloc(NULL, 12, 1, 5, 6, &mclass, 4096, 4, 4096, &tree);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_tree_replay_process_txn(c1, tree);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_tree_replay_process_kvb(c1, tree);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

#if 0
    for (i = 0; i < 10; i++) {
        mapi_inject_once(mapi_idx_mpool_mlog_append, i,
                 merr(ev(EIO)));
        err = c0_put(test_c0, &kt, &vt, seqnoref);
        if (!err)
            c0_sync(test_c0);
        mapi_inject_unset(mapi_idx_mpool_mlog_append);
    }

    for (i = 0; i < 10; i++) {
        mapi_inject_once(mapi_idx_mpool_mlog_append, i,
                 merr(ev(EIO)));
        err = c0_put(test_c0, &kt, &vt, seqnoref);
        if (!err)
            c0_sync(test_c0);
        mapi_inject_unset(mapi_idx_mpool_mlog_append);
    }

    for (i = 0; i < 10; i++) {
        mapi_inject_once(mapi_idx_mpool_mlog_sync, i, merr(EIO));
        err = c0_put(test_c0, &kt, &vt, seqnoref);
        if (!err)
            c0_sync(test_c0);
        mapi_inject_unset(mapi_idx_mpool_mlog_sync);
    }
#endif
    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0sk_close(mkvdb.ikdb_c0sk);

    err = c1_tree_close(tree);
    ASSERT_EQ(0, err);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();

    if (repeat) {
        kvdb_rp.perfc_enable = !perfc_verbosity;
        repeat = false;
        goto again;
    }
}

static bool
_c1_is_clean(struct c1 *c1)
{
    return false;
}

MTF_DEFINE_UTEST_PREPOST(c1_test, ingest_replay, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    merr_t              err;
    uintptr_t           seqnoref;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    mapi_inject(mapi_idx_ikvdb_flush, 0);

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    /*
    kt.kt_len = 3;
    kt.kt_data = "foo";
    */
    kvs_ktuple_init(&kt, "foo", 3);
    seqnoref = HSE_ORDNL_TO_SQNREF(0);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    vt.vt_data = "data";
    vt.vt_len = strlen(vt.vt_data);
    err = c0_put(test_c0, &kt, &vt, seqnoref);

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    destroy_mock_cn(mock_cn);

    c0sk_close(mkvdb.ikdb_c0sk);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    MOCK_SET(c1, _c1_is_clean);
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    mapi_inject(mapi_idx_malloc, 0);
    err = c1_journal_replay_impl(c1, NULL, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_malloc);

    mapi_inject(mapi_idx_mpool_mdc_rewind, merr(ENOMEM));
    err = c1_journal_replay_impl(c1, NULL, NULL);
    ASSERT_EQ(ENOMEM, merr_errno(err));
    mapi_inject_unset(mapi_idx_mpool_mdc_rewind);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    c1_unmock_mpool();
    MOCK_UNSET(c1, _c1_is_clean);
    mapi_inject_unset(mapi_idx_ikvdb_flush);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, ingest_replay2, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    merr_t              err;
    uintptr_t           seqnoref;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;
    int                 i;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    mapi_inject(mapi_idx_ikvdb_flush, 0);

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    /*
    kt.kt_len = 3;
    kt.kt_data = "foo";
    */
    kvs_ktuple_init(&kt, "foo", 3);
    seqnoref = HSE_ORDNL_TO_SQNREF(0);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    vt.vt_data = "data";
    vt.vt_len = strlen(vt.vt_data);
    err = c0_put(test_c0, &kt, &vt, seqnoref);

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    c0sk_close(mkvdb.ikdb_c0sk);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    MOCK_SET(c1, _c1_is_clean);

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    for (i = 0; i < 16; i++) {
        mapi_inject_once(mapi_idx_malloc, i, 0);
        err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
        if (!err)
            c1_close(c1);
        else {
            err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
            ASSERT_EQ(0, err);

            err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
            ASSERT_EQ(0, err);
        }
        mapi_inject_unset(mapi_idx_malloc);
    }

#if 0
    for (i = 0; i < 5; i++) {
        mapi_inject_once(mapi_idx_mpool_mlog_seek_read, i,
                 merr(ev(EIO)));
        err = c1_open(NULL, false, c1_oid1, c1_oid2, 0,
                 "mock_mp", &kvdb_rp, NULL, NULL, &c1);
        if (!err)
            c1_close(c1);
        mapi_inject_unset(mapi_idx_mpool_mlog_seek_read);
    }

    for (i = 0; i < 5; i++) {
        mapi_inject_once(mapi_idx_mpool_mlog_rewind, i,
                 merr(ev(EIO)));
        err = c1_open(NULL, false, c1_oid1, c1_oid2, 0,
                 "mock_mp", &kvdb_rp, NULL, NULL, &c1);
        if (!err)
            c1_close(c1);
        mapi_inject_unset(mapi_idx_mpool_mlog_rewind);
    }
#endif

    c1_unmock_mpool();
    destroy_mock_cn(mock_cn);
    MOCK_UNSET(c1, _c1_is_clean);
    mapi_inject_unset(mapi_idx_ikvdb_flush);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, ingest_replay3, no_fail_pre, no_fail_post)
{
    struct kvdb_rparams kvdb_rp;
    struct kvs_rparams  kvs_rp;
    struct c0 *         test_c0 = 0;
    struct kvs_ktuple   kt;
    struct kvs_vtuple   vt;
    merr_t              err;
    uintptr_t           seqnoref;
    struct mock_kvdb    mkvdb;
    struct cn *         mock_cn;
    atomic64_t          seqno;
    struct c1 *         c1 = NULL;
    struct kvdb_cparams kvdb_cp;
    u64                 c1_oid1;
    u64                 c1_oid2;

    kvdb_rp = kvdb_rparams_defaults();
    kvs_rp = kvs_rparams_defaults();
    kvdb_cp = kvdb_cparams_defaults();

    kvdb_rp.dur_buf_sz = 8;
    kvdb_rp.dur_intvl_ms = 100;

    kvdb_rp.c0_ingest_width = 1;

    mapi_inject(mapi_idx_ikvdb_flush, 0);

    atomic64_set(&seqno, 0);
    err = c0sk_open(&kvdb_rp, 0, "mock_mp", &mock_health, csched, &seqno, &mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);
    ASSERT_NE((struct c0sk *)0, mkvdb.ikdb_c0sk);

    err = c0skm_open(mkvdb.ikdb_c0sk, &kvdb_rp, c1, "mock_mp");
    ASSERT_EQ(0, err);

    err = create_mock_cn(&mock_cn, false, false, &kvs_rp, 0);
    ASSERT_EQ(0, err);

    err = c0_open((struct ikvdb *)&mkvdb, &kvs_rp, mock_cn, 0, &test_c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, test_c0);

    c1_mock_mpool();

    err = c1_alloc(NULL, &kvdb_cp, &c1_oid1, &c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_make(NULL, &kvdb_cp, c1_oid1, c1_oid2);
    ASSERT_EQ(0, err);

    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_EQ(0, err);

    kvs_ktuple_init(&kt, "foo", 3);
    seqnoref = HSE_ORDNL_TO_SQNREF(0);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    err = c0_del(test_c0, &kt, seqnoref);
    ASSERT_EQ(0, err);

    vt.vt_data = "data";
    vt.vt_len = strlen(vt.vt_data);
    err = c0_put(test_c0, &kt, &vt, seqnoref);

    err = c1_close(c1);
    ASSERT_EQ(0, err);

    err = c0_close(test_c0);
    ASSERT_EQ(0, err);

    c0skm_close(mkvdb.ikdb_c0sk);

    err = c0sk_close(mkvdb.ikdb_c0sk);
    ASSERT_EQ(0, err);

    MOCK_SET(c1, _c1_is_clean);

    mapi_inject(mapi_idx_mpool_mdc_cstart, merr(EIO));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_mpool_mdc_cstart);

    mapi_inject(mapi_idx_mpool_mdc_cend, merr(EIO));
    err = c1_open(NULL, false, c1_oid1, c1_oid2, 0, "mock_mp", &kvdb_rp, NULL, NULL, &c1);
    ASSERT_NE(0, err);
    mapi_inject_unset(mapi_idx_mpool_mdc_cend);

    MOCK_UNSET(c1, _c1_is_clean);

    destroy_mock_cn(mock_cn);

    c1_unmock_mpool();
    mapi_inject_unset(mapi_idx_ikvdb_flush);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, upgrade1, no_fail_pre, no_fail_post)
{
    struct c1_info_omf info_omf = {};
    struct c1_ver_omf  ver_omf = {};
    union c1_record    rec = {};
    struct c1_header   hdr;
    struct c1_version  ver;

    u32    len;
    merr_t err;
    char * omf;

    omf = (char *)&info_omf;

    /* c1_record_unpack */

    err = c1_record_unpack(NULL, C1_VERSION, &rec);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c1_record_unpack(omf, C1_VERSION, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, 5, sizeof(info_omf));
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(EPROTO, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, 10, sizeof(info_omf));
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(EPROTO, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, 26, sizeof(info_omf));
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(EPROTO, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, 50, sizeof(info_omf));
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(EPROTO, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, C1_TYPE_INFO, sizeof(info_omf));
    omf_set_c1info_seqno(&info_omf, 100);

    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.f.c1i_seqno, 100);

    /* c1_record_unpack_bytype */

    err = c1_record_unpack_bytype(NULL, C1_TYPE_INFO, C1_VERSION, &rec);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c1_record_unpack_bytype(omf, C1_VERSION, C1_TYPE_INFO, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c1_record_unpack_bytype(omf, 5, C1_VERSION, &rec);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = c1_record_unpack_bytype(omf, 26, C1_VERSION, &rec);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = c1_record_unpack_bytype(omf, C1_TYPE_INFO, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.f.c1i_seqno, 100);

    /* c1_record_omf2len */

    err = c1_record_omf2len(NULL, C1_VERSION, &len);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c1_record_omf2len(omf, C1_VERSION, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, 5, sizeof(info_omf));
    err = c1_record_omf2len(omf, C1_VERSION, &len);
    ASSERT_EQ(EPROTO, merr_errno(err));

    c1_set_hdr(&info_omf.hdr, C1_TYPE_INFO, sizeof(info_omf));
    err = c1_record_omf2len(omf, C1_VERSION, &len);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(len, sizeof(info_omf));

    /* c1_record_type2len */

    err = c1_record_type2len(5, C1_VERSION, &len);
    ASSERT_EQ(EPROTO, merr_errno(err));

    err = c1_record_type2len(C1_TYPE_INFO, C1_VERSION, &len);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(len, sizeof(info_omf));

    /* omf_c1_header_unpack */
    err = omf_c1_header_unpack(NULL, &hdr);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = omf_c1_header_unpack(omf, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* omf_c1_ver_unpack */
    err = omf_c1_ver_unpack(NULL, &ver);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = omf_c1_ver_unpack(omf, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    c1_set_hdr(&ver_omf.hdr, C1_TYPE_VERSION, sizeof(struct c1_hdr_omf));
    omf = (char *)&info_omf;
    err = omf_c1_ver_unpack(omf, &ver);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c1_record_type2len(C1_TYPE_VERSION, C1_VERSION, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));
}

void
upgrade_test(char *omf, struct c1_hdr_omf *hdr, u32 type, u32 omf_len, struct mtf_test_info *lcl_ti)
{
    union c1_record rec = {};

    u32    len;
    merr_t err;

    c1_set_hdr(hdr, type, sizeof(*hdr));
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = c1_record_type2len(type, C1_VERSION, &len);
    ASSERT_EQ(0, err);
    ASSERT_EQ(len, omf_len);
}

void
upgrade_test_bytype(char *omf, u32 type, u32 omf_len, struct mtf_test_info *lcl_ti)
{
    u32    len;
    merr_t err;

    err = c1_record_type2len(type, C1_VERSION, &len);
    ASSERT_EQ(0, err);
    ASSERT_EQ(len, omf_len);
}

MTF_DEFINE_UTEST_PREPOST(c1_test, upgrade2, no_fail_pre, no_fail_post)
{
    struct c1_info_omf     info_omf = {};
    struct c1_desc_omf     desc_omf = {};
    struct c1_ingest_omf   ing_omf = {};
    struct c1_kvlog_omf    kv_omf = {};
    struct c1_kvbundle_omf kvb_omf = {};
    struct c1_kvtuple_omf  kvt_omf = {};
    struct c1_complete_omf cmp_omf = {};
    struct c1_reset_omf    res_omf = {};
    struct c1_treetxn_omf  ttxn_omf = {};
    struct c1_vtuple_omf   vt_omf = {};
    struct c1_mblk_omf     mblk_omf = {};

    union c1_record rec = {};

    merr_t err;
    char * omf;

    /* C1_TYPE_INFO */
    omf = (char *)&info_omf;
    upgrade_test(omf, &info_omf.hdr, C1_TYPE_INFO, sizeof(info_omf), lcl_ti);

    /* C1_TYPE_DESC */
    omf = (char *)&desc_omf;
    upgrade_test(omf, &desc_omf.hdr, C1_TYPE_DESC, sizeof(desc_omf), lcl_ti);

    c1_set_hdr(&desc_omf.hdr, C1_TYPE_DESC, sizeof(desc_omf));
    omf_set_c1desc_gen(&desc_omf, 200);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.d.c1d_gen, 200);

    /* C1_TYPE_INGEST */
    omf = (char *)&ing_omf;
    upgrade_test(omf, &ing_omf.hdr, C1_TYPE_INGEST, sizeof(ing_omf), lcl_ti);

    c1_set_hdr(&ing_omf.hdr, C1_TYPE_INGEST, sizeof(ing_omf));
    omf_set_c1ingest_cnid(&ing_omf, 300);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.i.c1ing_cnid, 300);

    /* C1_TYPE_KVLOG */
    omf = (char *)&kv_omf;
    upgrade_test(omf, &kv_omf.hdr, C1_TYPE_KVLOG, sizeof(kv_omf), lcl_ti);

    c1_set_hdr(&kv_omf.hdr, C1_TYPE_KVLOG, sizeof(kv_omf));
    omf_set_c1kvlog_size(&kv_omf, 400);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.l.c1l_space, 400);

    /* C1_TYPE_KVB */
    omf = (char *)&kvb_omf;
    upgrade_test(omf, &kvb_omf.hdr, C1_TYPE_KVB, sizeof(kvb_omf), lcl_ti);

    c1_set_hdr(&kvb_omf.hdr, C1_TYPE_KVB, sizeof(kvb_omf));
    omf_set_c1kvb_txnid(&kvb_omf, 500);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.b.c1kvb_txnid, 500);

    /* C1_TYPE_KVT */
    omf = (char *)&kvt_omf;
    upgrade_test_bytype(omf, C1_TYPE_KVT, sizeof(kvt_omf), lcl_ti);

    omf_set_c1kvt_klen(&kvt_omf, 600);
    err = c1_record_unpack_bytype(omf, C1_TYPE_KVT, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.k.c1kvm_klen, 600);

    /* C1_TYPE_COMPLETE */
    omf = (char *)&cmp_omf;
    upgrade_test(omf, &cmp_omf.hdr, C1_TYPE_COMPLETE, sizeof(cmp_omf), lcl_ti);

    c1_set_hdr(&cmp_omf.hdr, C1_TYPE_COMPLETE, sizeof(cmp_omf));
    omf_set_c1comp_kvseqno(&cmp_omf, 700);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.c.c1c_kvseqno, 700);

    /* C1_TYPE_RESET */
    omf = (char *)&res_omf;
    upgrade_test(omf, &res_omf.hdr, C1_TYPE_RESET, sizeof(res_omf), lcl_ti);

    c1_set_hdr(&res_omf.hdr, C1_TYPE_RESET, sizeof(res_omf));
    omf_set_c1reset_newseqno(&res_omf, 800);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.r.c1reset_newseqno, 800);

    /* C1_TYPE_TXN */
    omf = (char *)&ttxn_omf;
    upgrade_test(omf, &ttxn_omf.hdr, C1_TYPE_TXN, sizeof(ttxn_omf), lcl_ti);

    c1_set_hdr(&ttxn_omf.hdr, C1_TYPE_TXN, sizeof(ttxn_omf));
    omf_set_c1ttxn_mutation(&ttxn_omf, 900);
    err = c1_record_unpack(omf, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.t.c1txn_mutation, 900);

    /* C1_TYPE_VT */
    omf = (char *)&vt_omf;
    upgrade_test_bytype(omf, C1_TYPE_VT, sizeof(vt_omf), lcl_ti);

    omf_set_c1vt_vlen(&vt_omf, 1000);
    err = c1_record_unpack_bytype(omf, C1_TYPE_VT, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.v.c1vm_vlen, 1000);

    /* C1_TYPE_MBLK */
    omf = (char *)&mblk_omf;
    upgrade_test_bytype(omf, C1_TYPE_MBLK, sizeof(mblk_omf), lcl_ti);

    omf_set_c1mblk_off(&mblk_omf, 1100);
    err = c1_record_unpack_bytype(omf, C1_TYPE_MBLK, C1_VERSION, &rec);
    ASSERT_EQ(0, err);
    ASSERT_EQ(rec.m.c1mblk_off, 1100);
}

merr_t
c1_unpack_v2(char *omf, union c1_record *rec, u32 *omf_len)
{
    *omf_len = 2;

    return 0;
}

merr_t
c1_unpack_v3(char *omf, union c1_record *rec, u32 *omf_len)
{
    *omf_len = 3;

    return 0;
}

merr_t
c1_unpack_v5(char *omf, union c1_record *rec, u32 *omf_len)
{
    *omf_len = 5;

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(c1_test, upgrade3, no_fail_pre, no_fail_post)
{

    struct c1_unpack_hinfo hinfo[] = {
        { c1_unpack_v2, 2 },
        { c1_unpack_v3, 3 },
        { c1_unpack_v5, 5 },
    };

    struct c1_unpack_type utype = { hinfo, NELEM(hinfo) };

    c1_unpack_hdlr *uph;

    u32    len = 0;
    merr_t err;

    uph = c1_record_unpack_hdlr_get(&utype, 1);
    ASSERT_EQ(NULL, uph);

    uph = c1_record_unpack_hdlr_get(&utype, 2);
    ASSERT_NE(NULL, uph);
    err = uph(NULL, NULL, &len);
    ASSERT_EQ(0, err);
    ASSERT_EQ(2, len);

    uph = c1_record_unpack_hdlr_get(&utype, 3);
    ASSERT_NE(NULL, uph);
    err = uph(NULL, NULL, &len);
    ASSERT_EQ(3, len);

    uph = c1_record_unpack_hdlr_get(&utype, 4);
    ASSERT_NE(NULL, uph);
    err = uph(NULL, NULL, &len);
    ASSERT_EQ(3, len);

    uph = c1_record_unpack_hdlr_get(&utype, 5);
    ASSERT_NE(NULL, uph);
    err = uph(NULL, NULL, &len);
    ASSERT_EQ(5, len);

    uph = c1_record_unpack_hdlr_get(&utype, 100);
    ASSERT_NE(NULL, uph);
    err = uph(NULL, NULL, &len);
    ASSERT_EQ(5, len);
}

MTF_END_UTEST_COLLECTION(c1_test)
