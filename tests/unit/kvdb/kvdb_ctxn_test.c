/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/hse.h>

#include <hse_util/hse_err.h>
#include <hse_util/atomic.h>
#include <hse_util/seqno.h>
#include <hse_util/keylock.h>

#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/c0_kvset.h>
#include <hse_ikvdb/c0snr_set.h>
#include <hse_ikvdb/c0_kvmultiset.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <pthread.h>

#include <tools/key_generation.h>
#include <hse_ikvdb/tuple.h>
#include <support/random_buffer.h>

#include <mocks/mock_c0cn.h>

#include <kvdb/kvdb_ctxn_internal.h>
#include <kvdb/kvdb_keylock.h>
#include <kvdb/viewset.h>

#define MOCK_SET(group, func) mtfm_##group##func##_set(func)

u64                   tn_delay = 256 * 1000;
u64                   tn_timeout = 1000 * 60 * 5;
struct kvdb_ctxn_set *kvdb_ctxn_set;

int
mapi_pre(struct mtf_test_info *ti)
{
    srand(time(NULL));

    mapi_inject_clear();

    mapi_inject(mapi_idx_kvdb_keylock_lock, 0);
    mapi_inject(mapi_idx_kvdb_keylock_list_lock, 0);
    mapi_inject(mapi_idx_kvdb_keylock_list_unlock, 0);
    mapi_inject(mapi_idx_kvdb_keylock_enqueue_locks, 0);
    mapi_inject(mapi_idx_kvdb_keylock_expire, 0);

    mock_c0cn_set();

    return 0;
}

int
mapi_post(struct mtf_test_info *ti)
{
    mapi_inject_clear();

    mock_c0cn_unset();

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_ctxn_test)

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, alloc, mapi_pre, mapi_post)
{
    struct kvdb_ctxn *      handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    merr_t                  err;
    atomic_ulong            kvdb_seq, tseqno;

    atomic_set(&kvdb_seq, 1);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    mapi_calls_clear(mapi_idx_malloc);
    mapi_calls_clear(mapi_idx_free);
    ASSERT_EQ(0, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    mapi_inject_once_ptr(mapi_idx_alloc_aligned, 1, NULL);
    err = c0snr_set_create(&css);
    ASSERT_NE(0, err);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    mapi_calls_clear(mapi_idx_malloc);
    mapi_calls_clear(mapi_idx_free);
    ASSERT_EQ(0, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(0, handle);
    ASSERT_EQ(2, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    ASSERT_EQ(2, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(2, mapi_calls(mapi_idx_free));

    c0snr_set_destroy(css);
    c0snr_set_destroy(NULL);

    viewset_destroy(vs);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, alloc_fail, mapi_pre, mapi_post)
{
    struct kvdb_ctxn   *handle;
    struct viewset     *vs;
    struct c0snr_set   *css;
    merr_t              err;
    atomic_ulong        kvdb_seq, tseqno;

    atomic_set(&kvdb_seq, 1);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    mapi_inject_ptr(mapi_idx_malloc, 0);
    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_EQ(NULL, handle);

    kvdb_ctxn_free(0);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, begin, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_ctxn_impl  *ctxn;
    atomic_ulong            kvdb_seq, tseqno;
    const u64               initial_seq = 117UL;
    merr_t                  err;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    char                    kbuf[16], vbuf[16];
    uintptr_t               tmp_seqnoref;
    struct c0              *c0 = NULL; /* c0 is mocked */

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(0, handle);

    ctxn = kvdb_ctxn_h2r(handle);

    /* fail first allocation */
    mapi_inject_once(mapi_idx_malloc, 1, 0);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    sprintf(kbuf, "c017snap");
    kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_EQ(ENOMEM, merr_errno(err));

    kvdb_ctxn_abort(handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);
//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_EQ(0, err);

    ASSERT_EQ(initial_seq + 2, atomic_read(&kvdb_seq));
    ASSERT_EQ(atomic_read(&kvdb_seq) - 1, ctxn->ctxn_view_seqno);
    ASSERT_LE(viewset_horizon(vs), initial_seq + 4);
    ASSERT_TRUE(HSE_SQNREF_INDIRECT_P(ctxn->ctxn_seqref));
    tmp_seqnoref = HSE_SQNREF_TO_SQNREF(ctxn->ctxn_seqref);
    ASSERT_TRUE(HSE_SQNREF_UNDEF_P(tmp_seqnoref));
    ASSERT_FALSE(HSE_SQNREF_ABORTED_P(ctxn->ctxn_seqref));
    ASSERT_FALSE(HSE_SQNREF_INVALID_P(ctxn->ctxn_seqref));

    kvdb_ctxn_free(handle);

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
}
#endif

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, basic_commit, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct kvdb_ctxn_impl  *ctxn;
    const u64               initial_seq = 117UL;
    merr_t                  err;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    char                    kbuf[16], vbuf[16];
    struct c0              *c0 = NULL; /* c0 is mocked */
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    sprintf(kbuf, "c017snap");
    kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);
    ASSERT_LE(viewset_horizon(vs), initial_seq);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    ctxn = kvdb_ctxn_h2r(handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);
    ASSERT_EQ(initial_seq, ctxn->ctxn_view_seqno);

    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
    ASSERT_EQ(0, err);
    ASSERT_LE(viewset_horizon(vs), initial_seq + 1);

    err = kvdb_ctxn_commit(handle);
    ASSERT_EQ(0, err);

    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(ctxn->ctxn_seqref));
    ASSERT_FALSE(HSE_SQNREF_ABORTED_P(ctxn->ctxn_seqref));
    ASSERT_FALSE(HSE_SQNREF_INVALID_P(ctxn->ctxn_seqref));

    ASSERT_EQ(initial_seq, ctxn->ctxn_view_seqno);
    ASSERT_EQ(initial_seq + 2, HSE_SQNREF_TO_ORDNL(ctxn->ctxn_seqref));
    ASSERT_EQ(initial_seq + 3, atomic_read(&kvdb_seq));

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

/* Test that second "commit" on same handle fails.
 */
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, basic_commit_twice, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct c0              *c0 = NULL; /* c0 is mocked */
    const u64               initial_seq = 117UL;
    atomic_ulong            kvdb_seq, tseqno;
    merr_t                  err;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_commit(handle);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_commit(handle);
    ASSERT_NE(0, err);

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}

/* Must call "begin" before "commit"
 */
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, basic_commit_proto, mapi_pre, mapi_post)
{
    atomic_ulong            kvdb_seq, tseqno;
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct c0              *c0 = NULL; /* c0 is mocked */
    const u64               initial_seq = 117UL;
    merr_t                  err;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    err = kvdb_ctxn_commit(handle);
    ASSERT_NE(0, err);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_commit(handle);
    ASSERT_EQ(0, err);

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, basic_commit_seqno, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    const u64               initial_seq = 117UL;
    merr_t                  err;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    char                    kbuf[16], vbuf[16];
    struct c0              *c0 = NULL; /* c0 is mocked */
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    sprintf(kbuf, "c017snap");
    kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_EQ(0, err);
    err = kvdb_ctxn_commit(handle);
    ASSERT_EQ(0, err);

    kvdb_ctxn_free(handle);

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, basic_abort, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_ctxn_impl  *ctxn;
    struct c0              *c0 = NULL; /* c0 is mocked */
    merr_t                  err;
    atomic_ulong            kvdb_seq, tseqno;
    const u64               initial_seq = 117UL;

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    ctxn = kvdb_ctxn_h2r(handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    kvdb_ctxn_abort(handle);

    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(ctxn->ctxn_seqref));
    ASSERT_FALSE(HSE_SQNREF_ORDNL_P(ctxn->ctxn_seqref));
    ASSERT_TRUE(HSE_SQNREF_ABORTED_P(ctxn->ctxn_seqref));
    ASSERT_EQ(initial_seq + 1, atomic_read(&kvdb_seq));

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
}

/* "abort" can be called from any state.
 */
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, basic_abort_twice, mapi_pre, mapi_post)
{
    struct kvdb_ctxn   *handle;
    struct viewset     *vs;
    struct c0snr_set   *css;
    struct c0          *c0 = NULL; /* c0 is mocked */
    merr_t              err;
    const u64           initial_seq = 117UL;
    atomic_ulong        kvdb_seq, tseqno;

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(NULL, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    kvdb_ctxn_abort(handle);
    kvdb_ctxn_abort(handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    kvdb_ctxn_abort(handle);
    kvdb_ctxn_abort(handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, get_view_seqno, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct c0              *c0 = NULL; /* c0 is mocked */
    const u64               initial_seq = 117UL;
    u64                     view_seqno;
    merr_t                  err;
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    err = kvdb_ctxn_get_view_seqno(handle, &view_seqno);
    ASSERT_EQ(0, err);
    ASSERT_EQ(initial_seq, view_seqno);

    kvdb_ctxn_begin(handle);
    kvdb_ctxn_commit(handle);
    err = kvdb_ctxn_get_view_seqno(handle, &view_seqno);
    ASSERT_EQ(EPROTO, merr_errno(err));

    kvdb_ctxn_begin(handle);
    kvdb_ctxn_abort(handle);
    err = kvdb_ctxn_get_view_seqno(handle, &view_seqno);
    ASSERT_EQ(EPROTO, merr_errno(err));

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, get_state, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct c0              *c0 = NULL; /* c0 is mocked */
    const u64               initial_seq = 117UL;
    enum kvdb_ctxn_state    state;
    merr_t                  err;
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    atomic_set(&kvdb_seq, initial_seq);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_INVALID, state);

    err = kvdb_ctxn_begin(handle);
    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, state);

    kvdb_ctxn_commit(handle);
    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_COMMITTED, state);

    err = kvdb_ctxn_begin(handle);
    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(0, err);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, state);

    kvdb_ctxn_abort(handle);
    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_ABORTED, state);

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}

/* Simple transaction put/get/del testing...
 */
#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, put_get_del, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    enum kvdb_ctxn_state    state;
    const u64               initial_value = 117UL;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    merr_t                  err;
    u64                     key, val, buf;
//    enum key_lookup_res     res;
    struct kvs_buf          vbuf = {};
    struct c0              *c0 = NULL; /* c0 is mocked */
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    key = 1;
    val = 2;
    kvs_ktuple_init(&kt, &key, sizeof(key));
    kvs_vtuple_init(&vt, &val, sizeof(val));

    atomic_set(&kvdb_seq, initial_value);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_INVALID, state);

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_NE(0, err);

//    err = kvdb_ctxn_get(handle, c0, &kt, NULL, NULL);
//    ASSERT_NE(0, err);

//    err = kvdb_ctxn_del(handle, c0, &kt);
//    ASSERT_NE(0, err);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, state);

//    mapi_inject_once(mapi_idx_kvdb_keylock_lock, 1, merr(EAGAIN));

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_NE(0, err);

//    mapi_inject(mapi_idx_kvdb_keylock_lock, 0);

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_EQ(0, err);

    kvs_buf_init(&vbuf, &buf, sizeof(buf));

//    err = kvdb_ctxn_get(handle, c0, &kt, &res, &vbuf);
//    ASSERT_EQ(err, 0);
//    ASSERT_EQ(res, FOUND_VAL);

//    mapi_inject_once(mapi_idx_kvdb_keylock_lock, 1, merr(EAGAIN));

//    err = kvdb_ctxn_del(handle, c0, &kt);
//    ASSERT_NE(0, err);

//    mapi_inject(mapi_idx_kvdb_keylock_lock, 0);

//    err = kvdb_ctxn_del(handle, c0, &kt);
//    ASSERT_EQ(0, err);

    /* [HSE_REVISIT] Fix gets. */
    /* err = kvdb_ctxn_get(handle, c0, &kt, &res, &vbuf); */
    /* ASSERT_EQ(err, 0); */
    /* ASSERT_EQ(res, FOUND_TMB); */

    err = kvdb_ctxn_commit(handle);
    ASSERT_EQ(0, err);
    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_COMMITTED, state);

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_EQ(ECANCELED, merr_errno(err));

//    err = kvdb_ctxn_get(handle, c0, &kt, NULL, NULL);
//    ASSERT_EQ(ECANCELED, merr_errno(err));

//    err = kvdb_ctxn_del(handle, c0, &kt);
//    ASSERT_EQ(ECANCELED, merr_errno(err));

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

/* Simple transaction put/get/pdel testing...
 */
#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, put_get_pdel, mapi_pre, mapi_post)
{
    struct kvdb_ctxn       *handle;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    enum kvdb_ctxn_state    state;
    const u64               initial_value = 117UL;
    struct kvs_ktuple       kt, pkt;
    struct kvs_vtuple       vt;
    merr_t                  err;
    u64                     key[2], val, buf;
    struct kvs_buf          vbuf = {};
    struct c0              *c0 = NULL; /* c0 is mocked */
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    mapi_inject(mapi_idx_c0_get_pfx_len, sizeof(key[0]));
    key[0] = 1;
    key[1] = 2;
    val = 10;
    kvs_ktuple_init(&kt, &key, sizeof(key));
    kvs_ktuple_init(&pkt, &key[0], sizeof(key[0]));
    kvs_vtuple_init(&vt, &val, sizeof(val));

    atomic_set(&kvdb_seq, initial_value);
    atomic_set(&tsqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    handle = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, handle);

    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_INVALID, state);

    err = kvdb_ctxn_begin(handle);
    ASSERT_EQ(0, err);

    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, state);

//    err = kvdb_ctxn_put(handle, c0, &kt, &vt);
//    ASSERT_EQ(0, err);

    kvs_buf_init(&vbuf, &buf, sizeof(buf));

    /* err = kvdb_ctxn_get(handle, c0, &kt, &res, &vbuf); */
    /* ASSERT_EQ(err, 0); */
    /* ASSERT_EQ(res, FOUND_VAL); */

//    err = kvdb_ctxn_prefix_del(handle, c0, &pkt);
//    ASSERT_EQ(0, err);

    /* err = kvdb_ctxn_get(handle, c0, &kt, &res, &vbuf); */
    /* ASSERT_EQ(err, 0); */
    /* ASSERT_EQ(res, FOUND_VAL); */

    /* /\* same pfx, different key. Expect FOUND_PTMB *\/ */
    /* key[1] = 3; */
    /* err = kvdb_ctxn_get(handle, c0, &kt, &res, &vbuf); */
    /* ASSERT_EQ(err, 0); */
    /* ASSERT_EQ(res, FOUND_PTMB); */

    err = kvdb_ctxn_commit(handle);
    ASSERT_EQ(0, err);
    state = kvdb_ctxn_get_state(handle);
    ASSERT_EQ(KVDB_CTXN_COMMITTED, state);

    kvdb_ctxn_free(handle);
    kvdb_ctxn_set_destroy(kvdb_ctxn_set);

    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, txn_timeout, mapi_pre, mapi_post)
{
    merr_t                  err;
    int                     i;
    const int               num_txns = 32;
    enum kvdb_ctxn_state    state;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_ctxn_impl  *ctxn;
    struct kvdb_keylock    *klock;
    struct kvdb_ctxn       *handles[num_txns];
    const u64               initial_value = 117UL;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    char                    kbuf[16], vbuf[16];
    struct c0              *c0 = NULL; /* c0 is mocked */
    u32                     delay_ms = 500;
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    atomic_set(&kvdb_seq, initial_value);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, delay_ms, delay_ms / 5);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    for (i = 0; i < num_txns; i++) {
        handles[i] = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);

        sprintf(kbuf, "-%03d-", i);
        kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));

        err = kvdb_ctxn_begin(handles[i]);
        ASSERT_EQ(err, 0);

//        err = kvdb_ctxn_put(handles[i], c0, &kt, &vt);
//        ASSERT_EQ(err, 0);

        if (i % 2)
            kvdb_ctxn_commit(handles[i]);
    }

    /* Wait for kvdb_txn_set thread to run. (not guaranteed) */
    usleep(1000 * delay_ms * 6);

    for (i = 0; i < num_txns; i++) {
        if (i % 2 == 0) {
            err = kvdb_ctxn_commit(handles[i]);
            ASSERT_EQ(EINVAL, merr_errno(err));

            ctxn = kvdb_ctxn_h2r(handles[i]);
            ASSERT_TRUE(HSE_SQNREF_ABORTED_P(ctxn->ctxn_seqref));
        } else {
            state = kvdb_ctxn_get_state(handles[i]);
            ASSERT_EQ(KVDB_CTXN_COMMITTED, state);
        }
    }

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, txn_cleanup, mapi_pre, mapi_post)
{
    merr_t                  err;
    int                     i;
    const int               num_txns = 5;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct kvdb_ctxn       *handles[num_txns];
    const u64               initial_value = 117UL;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    char                    kbuf[16], vbuf[16];
    struct c0              *c0 = NULL; /* c0 is mocked */
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    sprintf(kbuf, "c017snap");
    kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    atomic_set(&kvdb_seq, initial_value);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    for (i = 0; i < num_txns; i++) {
        handles[i] = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
        err = kvdb_ctxn_begin(handles[i]);
        ASSERT_EQ(err, 0);
//        err = kvdb_ctxn_put(handles[i], c0, &kt, &vt);
//        ASSERT_EQ(err, 0);
    }

    kvdb_ctxn_abort(handles[0]);
    kvdb_ctxn_commit(handles[3]);

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

/* Try to detect if kvdb_ctxn_put() and kvdb_ctxn_del() are generating
 * the same hash for each given key.
 */
#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, txn_hash, mapi_pre, mapi_post)
{
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct kvdb_ctxn       *ctxn;
    struct c0              *c0 = NULL; /* c0 is mocked */
//    struct kvs_ktuple       kt;
//    struct kvs_vtuple       vt;
//    char                    kbuf[16];
    atomic_ulong            kvdb_seq, tseqno;
    merr_t                  err;
//    int                     i;

    mapi_inject_unset(mapi_idx_kvdb_keylock_lock);

    err = kvdb_keylock_create(&klock, 5);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    atomic_set(&kvdb_seq, time(NULL));
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    ctxn = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, ctxn);

    err = kvdb_ctxn_begin(ctxn);
    ASSERT_EQ(err, 0);

//    for (i = 0; i < 5 * 4096; ++i) {
//        snprintf(kbuf, sizeof(kbuf), "%d", i);
//        kvs_ktuple_init(&kt, kbuf, strlen(kbuf));

//        kvs_vtuple_init(&vt, &i, sizeof(i));

//        err = kvdb_ctxn_put(ctxn, c0, &kt, &vt);
//        if (err)
//            break;
//    }

    /* The keylock tables should be about 1/4 full, and it's not
     * possible to insert any more within this transaction due
     * to limits imposed by kvdb_keylock.
     */
//    ASSERT_GE(i, (5 * 4096) / 4);

    /* We should be able to delete all the keys we just put, because
     * the deletes should piggyback on the same key locks being held
     * by all the keys we put.
     */
//    while (i-- > 0) {
//        snprintf(kbuf, sizeof(kbuf), "%d", i);
//        kvs_ktuple_init(&kt, kbuf, strlen(kbuf));

//       err = kvdb_ctxn_del(ctxn, c0, &kt);
//       ASSERT_EQ(0, err);
//    }

    kvdb_ctxn_abort(ctxn);

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);
    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

/* Verify that we can insert identical keys into two different c0's
 * via two independent transactions.
 */
#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, txn_independence, mapi_pre, mapi_post)
{
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct kvdb_ctxn       *ctxn1, *ctxn2;
    struct c0              *c0a, *c0b;
    atomic_ulong            kvdb_seq, tseqno;
    merr_t                  err;
    int                     i;

    /* Note that c0 is mocked and these calls redirect to _c0_open().
     */
    err = c0_open(NULL, NULL, NULL, NULL, &c0a);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0a);

    err = c0_open(NULL, NULL, NULL, NULL, &c0b);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0b);

    mapi_inject_unset(mapi_idx_kvdb_keylock_lock);

    err = kvdb_keylock_create(&klock, 7);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    atomic_set(&kvdb_seq, time(NULL));
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    ctxn1 = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, ctxn1);

    err = kvdb_ctxn_begin(ctxn1);
    ASSERT_EQ(err, 0);

    ctxn2 = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
    ASSERT_NE(NULL, ctxn2);

    err = kvdb_ctxn_begin(ctxn2);
    ASSERT_EQ(err, 0);

    /* If the ctxn and keylock hashing is good and the tables are
     * sufficiently large then it's unlikely any of these puts will
     * fail.  However, keylock collisions are possible, and if you
     * find the asserts are tripping then simply try increasing the
     * number of keylock tables to the next higher prime number
     * (see kvdb_keylock_create() above).
     */
    for (i = 0; i < 1024; ++i) {
        struct kvs_ktuple kt;
        struct kvs_vtuple vt;
        char              kbuf[16];

        snprintf(kbuf, sizeof(kbuf), "%d", i);
        kvs_ktuple_init(&kt, kbuf, strlen(kbuf));

        kvs_vtuple_init(&vt, &i, sizeof(i));

//        err = kvdb_ctxn_put(ctxn1, c0a, &kt, &vt);
//        ASSERT_EQ(0, err);

//        err = kvdb_ctxn_put(ctxn2, c0b, &kt, &vt);
//        ASSERT_EQ(0, err);
    }

    kvdb_ctxn_abort(ctxn1);
    kvdb_ctxn_abort(ctxn2);

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);
    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);

    c0_close(c0b);
    c0_close(c0a);
}
#endif

MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, seq_state, mapi_pre, mapi_post)
{
    enum kvdb_ctxn_state state;
    uintptr_t            seq;
    uintptr_t            ref;

    seq = HSE_SQNREF_UNDEFINED;
    state = seqnoref_to_state(seq);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, state);

    ref = HSE_REF_TO_SQNREF(&seq);
    state = seqnoref_to_state(ref);
    ASSERT_EQ(KVDB_CTXN_ACTIVE, state);
}

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, txn_seq, mapi_pre, mapi_post)
{
    merr_t                  err;
    int                     i;
    const int               num_txns = 256;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct kvdb_ctxn       *handles[num_txns];
    const u64               initial_value = 117UL;
    struct kvs_ktuple       kt;
    struct kvs_vtuple       vt;
    char                    kbuf[16], vbuf[16];
    struct c0              *c0 = NULL; /* c0 is mocked */
    u64                     horizon, curr_seq;
    u32                     delay_us;
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    sprintf(kbuf, "c017sna");
    kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));
    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    atomic_set(&kvdb_seq, initial_value);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    delay_us = 3000;
    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, delay_us / 1000);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    horizon = viewset_horizon(vs);
    ASSERT_EQ(horizon, initial_value);

    for (i = 0; i < num_txns; i++) {
        handles[i] = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);

        err = kvdb_ctxn_begin(handles[i]);
        ASSERT_EQ(err, 0);

//        err = kvdb_ctxn_put(handles[i], c0, &kt, &vt);
//        ASSERT_EQ(err, 0);
    }

    curr_seq = viewset_horizon(vs);
    ASSERT_EQ(horizon, curr_seq);

    for (i = 0; i < num_txns; i++) {
        if (rand() % 5)
            kvdb_ctxn_commit(handles[i]);
        else
            kvdb_ctxn_abort(handles[i]);

        curr_seq = viewset_horizon(vs);
        ASSERT_LE(horizon, curr_seq);
        ASSERT_LE(curr_seq, atomic_read(&kvdb_seq));

        horizon = curr_seq;
    }

    for (i = 0; i < num_txns / 3; i += 3)
        kvdb_ctxn_free(handles[i]);

    horizon = viewset_horizon(vs);
    ASSERT_EQ(horizon, atomic_read(&kvdb_seq));

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

struct parallel_ctxn_arg {
    struct kvdb_ctxn *ctxn;
    int               thrd_num;
    int               txn_num;
    atomic_t *        owner_thread;
};

#if 0
void *
parallel_ctxn_helper(void *arg)
{
    struct parallel_ctxn_arg *p = (struct parallel_ctxn_arg *)arg;
    struct kvdb_ctxn *        ctxn = p->ctxn;
    int                       thrd_num = p->thrd_num;
    int                       txn_num = p->txn_num;
    atomic_t *                owner_thread = p->owner_thread;
    merr_t                    err = 0;
//    int                       i;
//    struct kvs_ktuple         kt;
//    struct kvs_vtuple         vt;
//    char                      kbuf[16], vbuf[16];
    struct c0 *               c0 = NULL; /* c0 is mocked */
//    enum key_lookup_res       res;
//    struct kvs_buf            valbuf = {};

//    kvs_vtuple_init(&vt, vbuf, sizeof(vbuf));

    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    VERIFY_EQ_RET(0, err, 0);
    VERIFY_NE_RET(NULL, c0, 0);

//    for (i = 0; i < 1000; i++) {
//        sprintf(kbuf, "%03dsna%03d", i, i);
//        kvs_ktuple_init(&kt, kbuf, 1 + strlen(kbuf));

//        kvdb_ctxn_put(ctxn, c0, &kt, &vt);
//        kvdb_ctxn_get(ctxn, c0, &kt, &res, &valbuf);
//        kvdb_ctxn_del(ctxn, c0, &kt);
//    }

    /* A transaction can be committed successfully at most once. */
    err = kvdb_ctxn_commit(ctxn);
    if (err == 0) {
        int old = 0;
        bool b;

        b = atomic_cmpxchg(owner_thread + txn_num, &old, thrd_num);

        VERIFY_TRUE_RET(b, 0);
    }

    VERIFY_EQ_RET(atomic_read(owner_thread + txn_num) == thrd_num, err == 0, 0);

    return 0;
}
#endif

#if 0
MTF_DEFINE_UTEST_PREPOST(kvdb_ctxn_test, multiple_ctxn_commit, mapi_pre, mapi_post)
{
    const int                num_threads = 96;
    pthread_t                thread_idv[num_threads];
    struct parallel_ctxn_arg argstruct[num_threads];

    merr_t                  err;
    int                     i, rc;
    const int               num_txns = 32;
    struct viewset         *vs;
    struct c0snr_set       *css;
    struct kvdb_keylock    *klock;
    struct c0              *c0 = NULL; /* c0 is mocked */
    struct kvdb_ctxn       *handles[num_txns];
    atomic_t                owner_thread[32] = {};
    const u64               initial_value = 117UL;
    atomic_ulong            kvdb_seq, tseqno;

    err = kvdb_keylock_create(&klock, 16);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, klock);

    mapi_inject(mapi_idx_c0_get_pfx_len, sizeof(u64));

    atomic_set(&kvdb_seq, initial_value);
    atomic_set(&tseqno, 0);

    err = viewset_create(&vs, &kvdb_seq, &tseqno);
    ASSERT_TRUE(err == 0);

    err = kvdb_ctxn_set_create(&kvdb_ctxn_set, tn_timeout, tn_delay);
    ASSERT_EQ(err, 0);

    err = c0snr_set_create(&css);
    ASSERT_TRUE(err == 0);

    err = c0_open(NULL, NULL, NULL, NULL, &c0);
    ASSERT_EQ(0, err);
    ASSERT_NE(NULL, c0);

    for (i = 0; i < num_txns; i++) {
        handles[i] = kvdb_ctxn_alloc(klock, NULL, &kvdb_seq, kvdb_ctxn_set, vs, css, NULL, NULL);
        err = kvdb_ctxn_begin(handles[i]);
        ASSERT_EQ(err, 0);
    }

    for (i = 0; i < num_threads; i++) {
        argstruct[i].ctxn = handles[i % num_txns];
        argstruct[i].txn_num = i % num_txns;
        argstruct[i].thrd_num = i + 1;
        argstruct[i].owner_thread = owner_thread;

        rc = pthread_create(thread_idv + i, 0, parallel_ctxn_helper, &argstruct[i]);
        ASSERT_EQ(0, rc);
    }

    for (i = 0; i < num_threads; i++) {
        rc = pthread_join(thread_idv[i], 0);
        ASSERT_EQ(0, rc);
    }

    kvdb_ctxn_set_destroy(kvdb_ctxn_set);
    c0snr_set_destroy(css);

    viewset_destroy(vs);
    kvdb_keylock_destroy(klock);
}
#endif

MTF_END_UTEST_COLLECTION(kvdb_ctxn_test);
