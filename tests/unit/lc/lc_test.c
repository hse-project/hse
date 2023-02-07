/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>
#include <hse/test/mock/api.h>

#include <hse/util/bonsai_tree.h>
#include <hse/util/seqno.h>
#include <hse/util/keycmp.h>

#include <hse/ikvdb/tuple.h>
#include <hse/ikvdb/lc.h>
#include <hse/ikvdb/cursor.h>
#include <hse/ikvdb/kvdb_health.h>

struct lc *lc;
struct kvdb_health mock_health;

int
test_collection_setup(struct mtf_test_info *info)
{
    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    return 0;
}

static int
test_pre(struct mtf_test_info *lcl_ti)
{
    merr_t err;

    err = lc_create(&lc, &mock_health);
    ASSERT_EQ_RET(0, err, -1);

    lc_ingest_seqno_set(lc, 0);

    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    lc_destroy(lc);
    lc = NULL;
    return 0;
}

/* Helpers */
#define MAX_VALS_PER_KV 32

struct v_elem {
    uintptr_t seqnoref;
    char *    val;
};

struct kv_elem {
    const uint16_t skidx;
    char * key;
    struct v_elem val[MAX_VALS_PER_KV];
};

#define SO(_s, _val)                  \
    {                                 \
        HSE_ORDNL_TO_SQNREF(_s), _val \
    }

#define SR(_s, _val)                \
    {                               \
        HSE_REF_TO_SQNREF(_s), _val \
    }

static void
insert_keys(struct mtf_test_info *lcl_ti, uint elemc, struct kv_elem *elemv)
{
    struct bonsai_kv * bkv_vec;
    struct bonsai_val *val_vec;
    struct lc_builder *lcb;
    uint               num_vals;
    int                i, j, v;
    merr_t             err;

    num_vals = 0;
    for (i = 0; i < elemc; i++)
        for (j = 0; elemv[i].val[j].val; j++)
            num_vals++;

    bkv_vec = calloc(elemc, sizeof(*bkv_vec));
    ASSERT_NE(0, bkv_vec);

    val_vec = calloc(num_vals, sizeof(*val_vec));
    ASSERT_NE(0, val_vec);

    err = lc_builder_create(lc, &lcb);
    ASSERT_EQ(0, err);

    for (i = 0, v = 0; i < elemc; i++) {
        int                 j = 0;
        struct bonsai_val * vlist = NULL;
        struct bonsai_val **vprev;
        struct bonsai_kv *  bkv;

        bkv = &bkv_vec[i];
        bkv->bkv_key = elemv[i].key;
        key_immediate_init(elemv[i].key, strlen(elemv[i].key), elemv[i].skidx, &bkv->bkv_key_imm);
        /* ... ignore the other bkv fields */

        vprev = &vlist;
        while (elemv[i].val[j].val) {
            struct v_elem *    ve = &elemv[i].val[j++];
            struct bonsai_val *val = &val_vec[v++];

            val->bv_seqnoref = ve->seqnoref;
            val->bv_xlen = HSE_CORE_IS_TOMB(ve->val) ? 0 : strlen(ve->val);
            val->bv_value = ve->val;
            val->bv_priv = NULL;

            *vprev = val;
            vprev = &val->bv_priv;
        }

        err = lc_builder_add(lcb, bkv, vlist);
        ASSERT_EQ(0, err);
    }

    err = lc_builder_finish(lcb);
    ASSERT_EQ(0, err);

    lc_builder_destroy(lcb);

    free(val_vec);
    free(bkv_vec);
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(lc_test, test_collection_setup, test_collection_teardown);

MTF_DEFINE_UTEST_PREPOST(lc_test, put_get_basic, test_pre, test_post)
{
    merr_t err;
    char *key = "ab1";
    uint16_t skidx = 1;
    struct kvs_buf vbuf;
    enum key_lookup_res res;
    unsigned char valbuf[32];

    struct kv_elem elem[] = {
        { skidx, key, { SO(10, "ab1-val") } },
    };

    struct kvs_ktuple kt = {
        .kt_data = key,
        .kt_len = strlen(key),
    };

    insert_keys(lcl_ti, NELEM(elem), elem);

    kvs_buf_init(&vbuf, valbuf, sizeof(valbuf));
    err = lc_get(lc, skidx, 0, &kt, 100, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(FOUND_VAL, res);
}

MTF_DEFINE_UTEST_PREPOST(lc_test, put_get_multiple_vals, test_pre, test_post)
{
    merr_t err;
    uint16_t skidx = 1;
    struct kvs_buf vbuf;
    enum key_lookup_res res;
    unsigned char valbuf[32];

    struct kv_elem elem[] = {
        { skidx, "ab1", { SO(10, "val1"), SO(20, "val2") } },
    };

    struct kvs_ktuple kt = {
        .kt_data = "ab1",
        .kt_len = strlen("ab1"),
    };

    insert_keys(lcl_ti, NELEM(elem), elem);

    kvs_buf_init(&vbuf, valbuf, sizeof(valbuf));

    err = lc_get(lc, skidx, 0, &kt, 5, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(NOT_FOUND, res);

    err = lc_get(lc, skidx, 0, &kt, 11, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(FOUND_VAL, res);
    ASSERT_EQ(strlen("val1"), vbuf.b_len);
    ASSERT_EQ(0, memcmp(valbuf, "val1", vbuf.b_len));

    err = lc_get(lc, skidx, 0, &kt, 21, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(FOUND_VAL, res);
    ASSERT_EQ(strlen("val2"), vbuf.b_len);
    ASSERT_EQ(0, memcmp(valbuf, "val2", vbuf.b_len));
}

MTF_DEFINE_UTEST_PREPOST(lc_test, put_get_with_ptomb, test_pre, test_post)
{
    merr_t err;
    uint16_t skidx = 1;
    struct kvs_buf vbuf;
    enum key_lookup_res res;
    unsigned char valbuf[32];

    struct kv_elem elem[] = {
        { skidx, "ab1", { SO(10, "val1"), SO(30, "val2") } },
        { skidx, "ab", { SO(20, HSE_CORE_TOMB_PFX) } },
    };

    struct kvs_ktuple kt = {
        .kt_data = "ab1",
        .kt_len = strlen("ab1"),
    };

    insert_keys(lcl_ti, NELEM(elem), elem);

    kvs_buf_init(&vbuf, valbuf, sizeof(valbuf));

    /* Get at seqno = 5: Should get back nothing */
    err = lc_get(lc, skidx, 0, &kt, 5, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(NOT_FOUND, res);

    /* Get at seqno = 11: Should get back val1 (at 10) */
    err = lc_get(lc, skidx, 0, &kt, 11, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(FOUND_VAL, res);
    ASSERT_EQ(strlen("val1"), vbuf.b_len);
    ASSERT_EQ(0, memcmp(valbuf, "val1", vbuf.b_len));

    /* Get at seqno = 21: Should get back ptomb (at 20) */
    err = lc_get(lc, skidx, 2, &kt, 21, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(FOUND_PTMB, res);

    /* Get at seqno = 31: Should get back val2 (at 30) */
    err = lc_get(lc, skidx, 0, &kt, 31, 0, &res, &vbuf);
    ASSERT_EQ(0, err);
    ASSERT_EQ(FOUND_VAL, res);
    ASSERT_EQ(strlen("val2"), vbuf.b_len);
    ASSERT_EQ(0, memcmp(valbuf, "val2", vbuf.b_len));
}

static void
_lc_cursor_read(struct lc_cursor *cur, struct kvs_cursor_element *lc_elem, bool *eof)
{
    rcu_read_lock();
    lc_cursor_read(cur, lc_elem, eof);
    rcu_read_unlock();
}

static void
_lc_cursor_seek(struct lc_cursor *cur, const void *seek, size_t seeklen, struct kc_filter *filter)
{
    lc_cursor_seek(cur, seek, seeklen, filter);
}

static void
check_kv(
    struct mtf_test_info *     lcl_ti,
    struct kvs_cursor_element *e,
    bool                       eof,
    const char *               key,
    const char *               val)
{
    unsigned char kbuf[32];
    uint          klen;

    ASSERT_EQ(false, eof);

    key_obj_copy(kbuf, sizeof(kbuf), &klen, &e->kce_kobj);
    ASSERT_EQ(0, keycmp(kbuf, klen, key, strlen(key)));

    if (!val)
        return;

    if (HSE_CORE_IS_TOMB(val)) {
        ASSERT_EQ(val, e->kce_vt.vt_data);
        ASSERT_EQ(0, e->kce_vt.vt_xlen);
    } else {
        ASSERT_EQ(strlen(val), e->kce_vt.vt_xlen);
        ASSERT_EQ(0, memcmp(val, e->kce_vt.vt_data, e->kce_vt.vt_xlen));
    }
}

MTF_DEFINE_UTEST_PREPOST(lc_test, cursor_fwd_basic, test_pre, test_post)
{
    const uint16_t skidx = 1;
    struct kv_elem elem[] = {
        { skidx, "ab20", { SO(1, "val4"), SO(1, "val5") } },
        { skidx, "ab10", { SO(1, "val1"), SO(2, "val2"), SO(1, "val3") } },
        { skidx, "ab30", { SO(2, "val6"), SO(1, "val7") } },
    };

    bool eof;
    merr_t err;
    struct lc_cursor *cur;
    struct kvs_cursor_element e;
    const uint64_t view_seq = 11;

    insert_keys(lcl_ti, NELEM(elem), elem);

    rcu_read_lock();
    err = lc_cursor_create(lc, skidx, view_seq, 0, false, "ab", strlen("ab"), 0, 0, &cur);
    ASSERT_EQ(0, err);
    rcu_read_unlock();

    /* Read keys from the beginning */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab10", "val2");

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val5");

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val6");

    /* Expect eof. Repeated calls must yield eof */
    for (int i = 0; i < 3; i++) {
        _lc_cursor_read(cur, &e, &eof);
        ASSERT_EQ(true, eof);
    }

    /* Seek to a key that exists */
    _lc_cursor_seek(cur, "ab20", strlen("ab20"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val5");

    /* Seek to a key that doesn't exist */
    _lc_cursor_seek(cur, "ab19", strlen("ab19"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val5");

    lc_cursor_destroy(cur);
}

MTF_DEFINE_UTEST_PREPOST(lc_test, cursor_rev_basic, test_pre, test_post)
{
    const uint16_t skidx = 1;
    struct kv_elem elem[] = {
        { skidx, "ab20", { SO(1, "val4"), SO(1, "val5") } },
        { skidx, "ab10", { SO(1, "val1"), SO(2, "val2"), SO(1, "val3") } },
        { skidx, "ab30", { SO(2, "val6"), SO(1, "val7") } },
    };

    bool eof;
    merr_t err;
    struct lc_cursor *cur;
    const uint64_t view_seq = 11;
    char pfx[HSE_KVS_KEY_LEN_MAX];
    struct kvs_cursor_element e;

    insert_keys(lcl_ti, NELEM(elem), elem);

    memset(pfx, 0xff, sizeof(pfx));
    memcpy(pfx, "ab", strlen("ab"));

    rcu_read_lock();
    err = lc_cursor_create(lc, skidx, view_seq, 0, true, pfx, strlen("ab"), 0, 0, &cur);
    ASSERT_EQ(0, err);
    rcu_read_unlock();

    /* Read keys from the beginning */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val6");

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val5");

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab10", "val2");

    /* Expect eof. Repeated calls must yield eof */
    for (int i = 0; i < 3; i++) {
        _lc_cursor_read(cur, &e, &eof);
        ASSERT_EQ(true, eof);
    }

    /* Seek to a key that exists */
    _lc_cursor_seek(cur, "ab20", strlen("ab20"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val5");

    /* Seek to a key that doesn't exist */
    _lc_cursor_seek(cur, "ab21", strlen("ab21"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val5");

    lc_cursor_destroy(cur);
}

MTF_DEFINE_UTEST_PREPOST(lc_test, cursor_fwd_ptomb, test_pre, test_post)
{
    const uint16_t skidx = 1;
    struct kv_elem elem[] = {
        { skidx, "ab", { SO(15, HSE_CORE_TOMB_PFX), SO(10, "val2") } },
        { skidx, "ab20", { SO(10, "val4"), SO(10, "val5") } },
        { skidx, "ab10", { SO(10, "val1"), SO(9, "val2"), SO(13, "val3") } },
        { skidx, "ab30", { SO(20, "val6"), SO(10, "val7") } },
        { skidx, "ab40", { SO(40, "val8") } },
    };

    bool eof;
    merr_t err;
    struct lc_cursor *cur;
    struct kvs_cursor_element e;
    const uint64_t view_seq = 30;

    insert_keys(lcl_ti, NELEM(elem), elem);

    rcu_read_lock();
    err =
        lc_cursor_create(lc, skidx, view_seq, 0, false, "ab", strlen("ab"), strlen("ab"), 0, &cur);
    ASSERT_EQ(0, err);
    rcu_read_unlock();

    /* Read all keys */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* should return ptomb */

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val6");

    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    /* Seeking to any key which has a matching ptomb should first
     * output the ptomb followed by the "found" key.
     */

    /* Read one key by seeking to an existing key */
    _lc_cursor_seek(cur, "ab20", strlen("ab20"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* first return the ptomb */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val6");

    /* Read one key by seeking to a non-existent key */
    _lc_cursor_seek(cur, "ab19", strlen("ab19"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* first return the ptomb */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val6");

    /* Past eof (based on seqno), expect ptomb followed by eof */
    _lc_cursor_seek(cur, "ab31", strlen("ab31"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX);
    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    /* Past eof (based on keyspace), expect ptomb followed by eof */
    _lc_cursor_seek(cur, "ab41", strlen("ab41"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX);
    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    lc_cursor_destroy(cur);
}

MTF_DEFINE_UTEST_PREPOST(lc_test, cursor_rev_ptomb, test_pre, test_post)
{
    const uint16_t skidx = 1;
    struct kv_elem elem[] = {
        { skidx, "ab", { SO(15, HSE_CORE_TOMB_PFX), SO(10, "val2") } },
        { skidx, "ab10", { SO(10, "val4"), SO(10, "val5") } },
        { skidx, "ab20", { SO(20, "val6"), SO(10, "val7") } },
        { skidx, "ab30", { SO(20, "val8") } },
        { skidx, "ab40", { SO(40, "val9") } },
    };

    bool eof;
    merr_t err;
    struct lc_cursor *cur;
    struct kvs_cursor_element e;
    const uint64_t view_seq = 30;
    char pfx[HSE_KVS_KEY_LEN_MAX];

    insert_keys(lcl_ti, NELEM(elem), elem);

    memset(pfx, 0xff, sizeof(pfx));
    memcpy(pfx, "ab", strlen("ab"));

    rcu_read_lock();
    err = lc_cursor_create(lc, skidx, view_seq, 0, true, pfx, strlen("ab"), strlen("ab"), 0, &cur);
    ASSERT_EQ(0, err);
    rcu_read_unlock();

    /* Read all keys */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* should return ptomb */

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val8");
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val6");

    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    /* Seeking to any key which has a matching ptomb should first
     * output the ptomb followed by the "found" key.
     */

    /* Read one key by seeking to an existing key */
    _lc_cursor_seek(cur, "ab20", strlen("ab20"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* first return the ptomb */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val6");

    /* Read one key by seeking to a non-existent key */
    _lc_cursor_seek(cur, "ab21", strlen("ab21"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* first return the ptomb */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab20", "val6");

    /* Seek to a key "before" cursor's view */
    _lc_cursor_seek(cur, "ab40", strlen("ab20"), 0);

    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX); /* first return the ptomb */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab30", "val8");

    /* Past eof (based on seqno), expect ptomb followed by eof */
    _lc_cursor_seek(cur, "ab19", strlen("ab19"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX);
    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    /* Past eof (based on keyspace), expect ptomb followed by eof */
    _lc_cursor_seek(cur, "ab09", strlen("ab09"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "ab", HSE_CORE_TOMB_PFX);
    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    lc_cursor_destroy(cur);
}

MTF_DEFINE_UTEST_PREPOST(lc_test, cursor_horizon, test_pre, test_post)
{
    bool eof;
    merr_t err;
    bool reverse = false;
    struct lc_cursor *cur;
    const uint16_t skidx = 1;
    struct kvs_cursor_element e;
    const uint64_t view_seq = 21;
    char pfx[HSE_KVS_KEY_LEN_MAX];
    struct kv_elem elem[] = {
        { skidx, "aa10", { SO(10, "val") } }, { skidx, "aa20", { SO(10, "val") } },
        { skidx, "bb10", { SO(10, "val") } }, { skidx, "bb20", { SO(20, "val") } },
        { skidx, "bb30", { SO(20, "val") } }, { skidx, "bb40", { SO(10, "val") } },
        { skidx, "zz10", { SO(10, "val") } }, { skidx, "zz20", { SO(10, "val") } },
    };

    insert_keys(lcl_ti, NELEM(elem), elem);

    lc_ingest_seqno_set(lc, 11); /* Set horizon seqno */

    rcu_read_lock();
    err = lc_cursor_create(
        lc, skidx, view_seq, 0, reverse, "bb", strlen("bb"), strlen("bb"), 0, &cur);
    ASSERT_EQ(0, err);
    rcu_read_unlock();

    /* Read all keys */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb20", "val");
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb30", "val");
    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    /* Read one key by seeking to an existing key */
    _lc_cursor_seek(cur, "bb20", strlen("bb20"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb20", "val");

    /* Read one key by seeking to a non-existent key */
    _lc_cursor_seek(cur, "ab20", strlen("ab20"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb20", "val");
    lc_cursor_destroy(cur);

    reverse = true;

    memset(pfx, 0xff, sizeof(pfx));
    memcpy(pfx, "bb", strlen("bb"));

    rcu_read_lock();
    err =
        lc_cursor_create(lc, skidx, view_seq, 0, reverse, pfx, strlen("bb"), strlen("bb"), 0, &cur);
    ASSERT_EQ(0, err);
    rcu_read_unlock();

    /* Read all keys */
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb30", "val");
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb20", "val");
    _lc_cursor_read(cur, &e, &eof);
    ASSERT_EQ(true, eof);

    /* Read one key by seeking to an existing key */
    _lc_cursor_seek(cur, "bb30", strlen("bb30"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb30", "val");

    /* Read one key by seeking to a non-existent key */
    _lc_cursor_seek(cur, "cb30", strlen("cb30"), 0);
    _lc_cursor_read(cur, &e, &eof);
    check_kv(lcl_ti, &e, eof, "bb30", "val");

    lc_cursor_destroy(cur);
}

MTF_END_UTEST_COLLECTION(lc_test)
