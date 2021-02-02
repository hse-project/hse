/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/hse_err.h>

#include <hse/hse.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_rparams.h>
#include <hse_ikvdb/kvs.h>

#include <kvdb/kvdb_log.h>

#include <mpool/mpool.h>

#include <hse_ikvdb/c0.h>
#include <mocks/mock_c0cn.h>

#include <mocks/mock_log.h>

struct kvs_cparams cp;

void
_hse_meminfo(ulong *freep, ulong *availp, uint shift)
{
    if (freep)
        *freep = 32;

    if (availp)
        *availp = 32;
}

/*
 * Pre and Post Functions
 */
static int
general_pre(struct mtf_test_info *ti)
{
    mapi_inject_clear();

    mapi_inject(mapi_idx_kvdb_log_open, 0);
    mapi_inject(mapi_idx_kvdb_log_close, 0);
    mapi_inject(mapi_idx_kvdb_log_rollover, 0);
    mapi_inject(mapi_idx_kvdb_log_compact, 0);
    mapi_inject(mapi_idx_kvdb_log_replay, 0);
    mapi_inject(mapi_idx_kvdb_log_done, 0);
    mapi_inject(mapi_idx_kvdb_log_abort, 0);
    mapi_inject(mapi_idx_cndb_replay, 0);
    mapi_inject(mapi_idx_cndb_cn_drop, 0);

    mapi_inject_ptr(mapi_idx_cndb_cn_cparams, &cp);

    mapi_inject(mapi_idx_mpool_mdc_open, 0);
    mapi_inject(mapi_idx_mpool_mdc_close, 0);

    mock_c0cn_set();
    mock_cndb_set();
    mapi_inject(mapi_idx_mpool_open, 0);
    mapi_inject(mapi_idx_mpool_close, 0);

    mapi_inject(mapi_idx_c0_get_pfx_len, 0);

    mapi_inject(mapi_idx_mpool_mclass_get, ENOENT);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION(kvdb_test)

MTF_DEFINE_UTEST_PRE(kvdb_test, kvdb_null_key_test, general_pre)
{
    struct mpool *         ds = (struct mpool *)-1;
    struct hse_kvdb *      kvdb_h;
    struct hse_kvs *       kvs_h = NULL;
    struct hse_kvdb_opspec opspec;
    const char *           mpool = "mpool";
    const char *           kvs = "kvs";
    uint64_t               err;
    bool                   found;
    char                   buf[100];
    size_t                 vlen;
    char                  *key, *val;
    size_t                 keylen, vallen;

    HSE_KVDB_OPSPEC_INIT(&opspec);

    err = ikvdb_open(mpool, ds, NULL, (struct ikvdb **)&kvdb_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, kvdb_h);

    err = hse_kvdb_kvs_make(kvdb_h, kvs, NULL);
    ASSERT_EQ(0, err);

    err = hse_kvdb_kvs_open(kvdb_h, kvs, 0, &kvs_h);
    ASSERT_EQ(0, err);

    key = "key";
    keylen = 0;
    val = "value";
    vallen = strlen(val);

    err = hse_kvs_put(kvs_h, &opspec, key, keylen, val, vallen);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = hse_kvs_delete(kvs_h, &opspec, key, keylen);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = hse_kvs_get(kvs_h, &opspec, key, keylen, &found, buf, sizeof(buf), &vlen);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = hse_kvs_prefix_delete(kvs_h, &opspec, key, keylen, 0);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = ikvdb_close((struct ikvdb *)kvdb_h);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_test, kvdb_getco_test, general_pre)
{
    struct mpool *         ds = (struct mpool *)-1;
    struct hse_kvdb *      kvdb_h = NULL;
    struct hse_kvs *       kvs_h = NULL;
    struct hse_kvdb_opspec opspec;
    const char *           mpool = "mpool";
    const char *           kvs = "kvs";
    uint64_t               err;
    bool                   found;
    char                   buf[100];
    size_t                 vlen;
    char                  *key, *val;
    size_t                 keylen, vallen;

    HSE_KVDB_OPSPEC_INIT(&opspec);

    err = ikvdb_open(mpool, ds, NULL, (struct ikvdb **)&kvdb_h);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, kvdb_h);

    err = hse_kvdb_kvs_make(kvdb_h, kvs, NULL);
    ASSERT_EQ(0, err);

    err = hse_kvdb_kvs_open(kvdb_h, kvs, 0, &kvs_h);
    ASSERT_EQ(0, err);

    key = "alpha";
    keylen = strlen(key);
    val = "beta";
    vallen = strlen(val);

    err = hse_kvs_put(kvs_h, &opspec, key, keylen, val, vallen);
    ASSERT_EQ(0, err);

    /*
     * - Call getco with an insufficiently sized buffer.
     * - Use the value len from the first call to getco to reallocate a
     *   buffer of the right size(emulated here by only setting
     *   opspec.kop_buf_len to val_len) and call getco again
     */

    /* insufficiently sized buffer */
    err = hse_kvs_get(kvs_h, &opspec, key, keylen, &found, buf, vallen - 2, &vlen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(found, true);
    ASSERT_EQ(vlen, vallen);

    /* correctly sized buffer */
    err = hse_kvs_get(kvs_h, &opspec, key, keylen, &found, buf, vlen, &vlen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(found, true);
    ASSERT_EQ(vlen, vallen);

    err = ikvdb_close((struct ikvdb *)kvdb_h);
    ASSERT_EQ(0, err);
}

MTF_DEFINE_UTEST_PRE(kvdb_test, kvdb_kvs_make_test, general_pre)
{
    struct hse_kvdb *  hdl = NULL;
    const char *       mpool = "mpool_alpha";
    uint64_t           err;
    struct mpool *     ds = (struct mpool *)-1;
    struct hse_params *params;
    int                len = HSE_KVS_NAME_LEN_MAX + 1;
    char               kvs[len];

    err = ikvdb_open(mpool, ds, NULL, (struct ikvdb **)&hdl);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, hdl);

    hse_params_create(&params);

    /* kvs name contains unsupported characters */
    err = hse_kvdb_kvs_make(hdl, "kvs%%42^^@", params);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* Null handle */
    err = hse_kvdb_kvs_make(NULL, "kvdb", params);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* kvs name too long */

    memset(kvs, 'a', len);
    kvs[len - 1] = '\0';
    err = hse_kvdb_kvs_make(hdl, kvs, params);
    ASSERT_EQ(ENAMETOOLONG, merr_errno(err));

    kvs[len - 2] = '\0';
    err = hse_kvdb_kvs_make(hdl, kvs, params);
    ASSERT_EQ(0, err);

    err = ikvdb_close((struct ikvdb *)hdl);
    ASSERT_EQ(0, err);

    hse_params_destroy(params);
}

MTF_DEFINE_UTEST_PRE(kvdb_test, kvdb_cursor_test, general_pre)
{
    struct hse_kvdb *      h;
    struct hse_kvs *       kvs;
    struct hse_kvs_cursor *cur;
    struct hse_kvdb_opspec os;

    struct hse_params *params;
    const void *kbuf, *vbuf;
    size_t      klen, vlen;
    bool        eof;
    int         rc;

    /*
     * This is just an API test, not mechanism.
     * c0, cn and cndb are mocked away, so these calls do nothing.
     */

    MOCK_SET(platform, _hse_meminfo);

    HSE_KVDB_OPSPEC_INIT(&os);

    hse_params_create(&params);
    rc = hse_kvdb_open("mp1", 0, &h);
    ASSERT_EQ(0, rc);
    ASSERT_NE(0, h);

    rc = hse_kvdb_kvs_make(h, "kv1", 0);
    ASSERT_EQ(0, rc);

    rc = hse_params_set(params, "kvs.transactions_enable", "1");
    ASSERT_EQ(0, rc);
    rc = hse_kvdb_kvs_open(h, "kv1", params, &kvs);
    ASSERT_EQ(0, rc);
    ASSERT_NE(0, kvs);

    os.kop_flags = 0;
    os.kop_txn = hse_kvdb_txn_alloc(h);
    ASSERT_NE(0, os.kop_txn);

    rc = hse_kvdb_txn_begin(h, os.kop_txn);
    ASSERT_EQ(0, rc);
    rc = hse_kvs_put(kvs, &os, "key", 3, "val", 3);
    ASSERT_EQ(0, rc);
    rc = hse_kvdb_txn_commit(h, os.kop_txn);
    ASSERT_EQ(0, rc);

    rc = hse_kvdb_txn_begin(h, os.kop_txn);
    ASSERT_EQ(0, rc);

    rc = hse_kvs_cursor_create(kvs, &os, 0, 0, &cur);
    ASSERT_EQ(0, rc);
    ASSERT_NE(0, cur);

    rc = hse_kvdb_txn_abort(h, os.kop_txn);
    ASSERT_EQ(0, rc);

    rc = hse_kvs_cursor_update(cur, 0);
    ASSERT_EQ(0, rc);

    /* repeat this test here for coverage of reuse case */
    rc = hse_kvdb_txn_begin(h, os.kop_txn);
    ASSERT_EQ(0, rc);

    rc = hse_kvdb_txn_abort(h, os.kop_txn);
    ASSERT_EQ(0, rc);

    rc = hse_kvs_cursor_update(cur, 0);
    ASSERT_EQ(0, rc);

    rc = hse_kvs_cursor_seek(cur, 0, "key", 3, 0, 0);
    ASSERT_EQ(0, rc);

    rc = hse_kvs_cursor_read(cur, 0, &kbuf, &klen, &vbuf, &vlen, &eof);
    ASSERT_EQ(0, rc);

    rc = hse_kvs_cursor_destroy(cur);
    ASSERT_EQ(0, rc);

    rc = hse_kvdb_close(h);
    ASSERT_EQ(0, rc);

    hse_params_destroy(params);

    MOCK_UNSET(platform, _hse_meminfo);
}

int64_t
_mpool_open(
    const char               *mp_name,
    const struct hse_params  *params,
    uint32_t                  flags,
    struct mpool            **dsp)
{
    *dsp = (struct mpool *)-1;
    return 0;
}

MTF_DEFINE_UTEST_PRE(kvdb_test, log_lvl_test, general_pre)
{
    uint64_t           rc;
    char *             str;
    struct hse_kvdb *  hdl;
    struct hse_params *params;
    char *             log;

    log = shared_result.msg_buffer;

    mapi_inject_unset(mapi_idx_mpool_open);
    MOCK_SET(mpool, _mpool_open);

    hse_params_create(&params);

    rc = hse_params_set(params, "kvdb.log_lvl", "8");
    ASSERT_EQ(0, rc);

    rc = hse_kvdb_open("mpool", params, &hdl);
    ASSERT_EQ(EINVAL, hse_err_to_errno(rc));

    hse_openlog("log_lvl_test", true);
    hse_log(HSE_CRIT "start test");

    rc = hse_params_set(params, "kvdb.log_lvl", "0");
    ASSERT_EQ(0, rc);

    str = "msg priority: alert(1): log level: 0";
    rc = hse_kvdb_open("mpool", params, &hdl);
    ASSERT_EQ(0, rc);
    hse_log(HSE_ALERT "%s", str);
    ikvdb_close((struct ikvdb *)hdl);
    ASSERT_FALSE(strstr(log, str));

    rc = hse_params_set(params, "kvdb.log_lvl", "1");
    ASSERT_EQ(0, rc);

    str = "msg priority: alert(1): log level: 1";
    rc = hse_kvdb_open("mpool", params, &hdl);
    ASSERT_EQ(0, rc);
    hse_log(HSE_ALERT "%s", str);
    ikvdb_close((struct ikvdb *)hdl);
    /* Fails due to a race condition with log message buffer */
    /* ASSERT_TRUE(strstr(log, str)); */

    rc = hse_params_set(params, "kvdb.log_lvl", "2");
    ASSERT_EQ(0, rc);

    str = "msg priority: alert(1): log level: 2";
    rc = hse_kvdb_open("mpool", params, &hdl);
    ASSERT_EQ(0, rc);
    hse_log(HSE_ALERT "%s", str);
    ikvdb_close((struct ikvdb *)hdl);
    /* Fails due to a race condition with log message buffer */
    // ASSERT_TRUE(strstr(log, str));

    hse_params_destroy(params);

    hse_closelog();

    MOCK_UNSET(mpool, _mpool_open);
}

MTF_DEFINE_UTEST(kvdb_test, health)
{
    struct kvdb_health health;

    uint   event, mask;
    merr_t err = 0;
    int    i;
    merr_t healtherr = merr(ENOANO);

    memset(&health, 0, sizeof(health));

    /* Test that a non-event doesn't trip an error.
     */
    err = kvdb_health_event(&health, KVDB_HEALTH_FLAG_NONE, healtherr);
    ASSERT_EQ(err, 0);

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, 0);

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_NONE);
    ASSERT_EQ(err, 0);

    err = kvdb_health_clear(&health, KVDB_HEALTH_FLAG_NONE);
    ASSERT_NE(err, 0);

    /* Trip, check, clear, and check each event type.
     */
    mask = KVDB_HEALTH_FLAG_ALL;
    for (event = 1; mask; event <<= 1) {
        if (event & mask) {
            err = kvdb_health_event(&health, event, healtherr);
            ASSERT_EQ(err, 0);

            err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
            ASSERT_EQ(err, healtherr);

            err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL & ~event);
            ASSERT_EQ(err, 0);

            err = kvdb_health_check(&health, event);
            ASSERT_EQ(err, healtherr);

            err = kvdb_health_clear(&health, event);
            ASSERT_EQ(err, 0);

            err = kvdb_health_check(&health, event);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }
    }

    /* Try to trip an invalid event.
     */
    err = kvdb_health_event(&health, event, healtherr);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = kvdb_health_clear(&health, event);
    ASSERT_EQ(EINVAL, merr_errno(err));

    /* Trip all events, check that each is tripped, then clear them all.
     */
    mask = KVDB_HEALTH_FLAG_ALL;
    for (event = 1; mask; event <<= 1) {
        if (event & mask) {
            err = kvdb_health_event(&health, event, healtherr);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }
    }

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, healtherr);

    mask = KVDB_HEALTH_FLAG_ALL;
    for (event = 1; mask; event <<= 1) {
        if (event & mask) {
            err = kvdb_health_check(&health, event);
            ASSERT_EQ(err, healtherr);

            err = kvdb_health_clear(&health, event);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }
    }

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, 0);

    /* errno 0 shouldn't trip an error
     */
    err = kvdb_health_error(&health, merr(0));
    ASSERT_EQ(err, 0);

    err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
    ASSERT_EQ(err, 0);

    /* Check that all non-zero errnos trip an event.
     */
    for (i = 1; i < 133; ++i) {
        err = kvdb_health_error(&health, merr(i));
        ASSERT_EQ(err, 0);

        err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
        ASSERT_NE(err, 0);

        /* Clear all events...
         */
        mask = KVDB_HEALTH_FLAG_ALL;
        for (event = 1; mask; event <<= 1) {
            err = kvdb_health_clear(&health, event);
            ASSERT_EQ(err, 0);

            mask &= ~event;
        }

        err = kvdb_health_check(&health, KVDB_HEALTH_FLAG_ALL);
        ASSERT_EQ(err, 0);
    }
}

MTF_END_UTEST_COLLECTION(kvdb_test);
