/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <fcntl.h>
#include <stdint.h>

#include <hse/test/mtf/framework.h>
#include <hse/test/mock/api.h>
#include <hse/test/support/random_buffer.h>

#include <hse/error/merr.h>
#include <hse/util/minmax.h>

#include <hse/mpool/mpool.h>
#include "mdc.h"
#include "mdc_file.h"

#include "common.h"

#define MDC_TEST_CAP (1 << 20)
#define MDC_TEST_MAGIC (0xabbaabba)

MTF_BEGIN_UTEST_COLLECTION_PRE(mdc_test, mpool_collection_pre)

MTF_DEFINE_UTEST_PREPOST(mdc_test, mdc_abc, mpool_test_pre, mpool_test_post)
{
    struct mpool     *mp;
    struct mpool_mdc *mdc;
    uint64_t          logid1, logid2, logid3, logid4;
    merr_t            err;
    size_t            used, alloc, size;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(NULL, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 1024, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_COUNT, &logid1, &logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_COUNT, NULL, &logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_COUNT, &logid1, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(EEXIST, merr_errno(err));

    err = mpool_mdc_abort(NULL, logid1, logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_abort(mp, logid1, logid1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_abort(mp, logid1, logid2 + 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_abort(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_abort(mp, logid1, logid2);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_STAGING, &logid3, &logid4);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, logid1);
    ASSERT_NE(0, logid2);

    err = mpool_mdc_commit(NULL, logid1, logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_commit(mp, logid1, logid1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_commit(mp, logid1, logid2 + 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_open(mp, logid1, logid2, false, &mdc);
    ASSERT_EQ(ENODATA, merr_errno(err));

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(NULL, logid1, logid2);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_delete(mp, logid1, logid1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_delete(mp, logid1, logid2 + 1);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_open(mp, logid1, logid1, false, &mdc);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_open(mp, logid1, logid2 + 1, false, &mdc);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_open(mp, logid1, logid2, false, &mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_cstart(NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_cstart(mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_cend(NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_cend(mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_close(NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_close(mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_open(mp, logid1, logid2, false, &mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_usage(NULL, NULL, NULL, &used);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_usage(mdc, NULL, NULL, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_usage(mdc, &size, &alloc, NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_usage(mdc, NULL, NULL, &used);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_usage(mdc, &size, &alloc, &used);
    ASSERT_EQ(0, err);
    ASSERT_EQ(MDC_TEST_CAP, size);
    ASSERT_EQ(MDC_LOGHDR_LEN, used);
    ASSERT_EQ(MDC_TEST_CAP, alloc);

    err = mpool_mdc_close(mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(ENOENT, merr_errno(err));

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    setup_mclass(HSE_MCLASS_STAGING);

    err = mpool_mclass_add(HSE_MCLASS_STAGING, &tcparams);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, merr_errno(err));

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, logid1);
    ASSERT_NE(0, logid2);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_STAGING, &logid3, &logid4);
    ASSERT_EQ(0, err);
    ASSERT_NE(0, logid3);
    ASSERT_NE(0, logid4);

    ASSERT_NE(logid1, logid3);
    ASSERT_NE(logid2, logid4);

    err = mpool_mdc_delete(mp, logid1, logid3);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_delete(mp, logid2, logid4);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(mp, logid3, logid4);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy(mtf_kvdb_home, &tdparams);
}

MTF_DEFINE_UTEST_PREPOST(mdc_test, mdc_io_basic, mpool_test_pre, mpool_test_post)
{
    struct mpool     *mp;
    struct mpool_mdc *mdc;

    uint64_t logid1, logid2;
    merr_t   err;
    int      iter;
    char    *buf, *rdbuf;
    size_t   bufsz = 16 << 10, rdlen;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, MDC_TEST_CAP, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    buf = malloc(bufsz);
    ASSERT_NE(NULL, buf);
    memset(buf, 'a', bufsz);

    rdbuf = calloc(1, bufsz);
    ASSERT_NE(NULL, rdbuf);

    err = mpool_mdc_open(mp, logid1, logid2, false, &mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_append(mdc, NULL, bufsz, true);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_append(NULL, buf, bufsz, true);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_read(mdc, rdbuf, bufsz, &rdlen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, rdlen);

    iter = 10;
    for (int i = 1; i <= iter; i++) {
        bool sync = (i == iter);
        err = mpool_mdc_append(mdc, buf, iter * i, sync);
        ASSERT_EQ(0, err);
    }

    err = mpool_mdc_sync(mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_read(NULL, rdbuf, bufsz, &rdlen);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_read(mdc, NULL, bufsz, &rdlen);
    ASSERT_EQ(EINVAL, merr_errno(err));

    for (int i = 1; i <= iter; i++) {
        err = mpool_mdc_read(mdc, rdbuf, bufsz, &rdlen);
        ASSERT_EQ(0, err);
        ASSERT_EQ(iter * i, rdlen);
        ASSERT_EQ(0, memcmp(rdbuf, buf, rdlen));
    }

    err = mpool_mdc_read(mdc, rdbuf, bufsz, &rdlen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, rdlen);

    err = mpool_mdc_rewind(NULL);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = mpool_mdc_rewind(mdc);
    ASSERT_EQ(0, err);
    memset(rdbuf, 0, bufsz);

    err = mpool_mdc_read(mdc, rdbuf, iter / 2, &rdlen);
    ASSERT_EQ(EOVERFLOW, merr_errno(err));
    ASSERT_EQ(iter, rdlen);

    for (int i = 1; i <= iter; i++) {
        err = mpool_mdc_read(mdc, rdbuf, bufsz, &rdlen);
        ASSERT_EQ(0, err);
        ASSERT_EQ(iter * i, rdlen);
        ASSERT_EQ(0, memcmp(rdbuf, buf, rdlen));
    }

    err = mpool_mdc_append(mdc, "testing", 7, false);
    ASSERT_EQ(0, err);

    err = mpool_mdc_read(mdc, rdbuf, bufsz, &rdlen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strncmp(rdbuf, "testing-extra-stuff", rdlen));

    err = mpool_mdc_read(mdc, rdbuf, bufsz, &rdlen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, rdlen);

    err = mpool_mdc_close(mdc);
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);
    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(buf);
    free(rdbuf);
}

static void
mdc_rw_test(
    struct mtf_test_info *lcl_ti,
    struct mpool         *mp,
    uint64_t              logid1,
    uint64_t              logid2,
    char                 *buf,
    size_t                bufsz,
    bool                  large)
{
    struct mpool_mdc *mdc;

    merr_t err;
    char  *rdbuf;
    size_t rdlen, reclen, rectot, reccnt, used, alloc, size;
    off_t  start;
    bool   sync;
    uint16_t reopen_freq, sync_freq;

    if (large) {
        reclen = 4 * 1024;
        reopen_freq = 8;
        sync_freq = 4;
    } else {
        reclen = 64;
        reopen_freq = 256;
        sync_freq = 128;
    }

    randomize_buffer(buf, bufsz, bufsz + 17);

    ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));

    rectot = 0;
    while (rectot < bufsz / reclen) {
        start = rectot * reclen;

        if (rectot == reopen_freq) {
            ASSERT_EQ(0, mpool_mdc_close(mdc));

            ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));
        }

        if (rectot % sync_freq == 0)
            sync = true;

        err = mpool_mdc_append(mdc, buf + start, reclen, sync);
        sync = false;

        if (!err) {
            ASSERT_EQ(0, mpool_mdc_usage(mdc, &size, &alloc, &used));
            ASSERT_NE(0, used);

            rectot = rectot + 1;
        } else if (merr_errno(err) == EFBIG) {
            ASSERT_EQ(0, mpool_mdc_usage(mdc, &size, &alloc, &used));
            ASSERT_GE(used, bufsz - 64);
            break;
        }
        ASSERT_EQ(0, err);
    }

    /*  read back log records */
    ASSERT_EQ(0, mpool_mdc_rewind(mdc));

    reccnt = 0;
    start = 0;

    rdbuf = calloc(reclen, sizeof(char));
    ASSERT_FALSE((char *)NULL == rdbuf);

    while (1) {
        err = mpool_mdc_read(mdc, rdbuf, reclen, &rdlen);
        if (!err) {
            if (rdlen == 0)
                break;

            if (rdlen == reclen) {
                if (memcmp(rdbuf, buf + start, reclen)) {
                    ASSERT_TRUE(0);
                } else {
                    reccnt = reccnt + 1;
                    start = start + reclen;
                    memset(rdbuf, 0, reclen);
                }
            } else {
                log_err("Failure rdlen %lu reclen %lu start %lu", rdlen, reclen, start);
                ASSERT_TRUE(0);
            }
        }
        ASSERT_EQ(0, err);
    }

    ASSERT_EQ(reccnt, rectot);

    ASSERT_EQ(0, mpool_mdc_close(mdc));

    free(rdbuf);
}

MTF_DEFINE_UTEST_PREPOST(mdc_test, mdc_io_advanced, mpool_test_pre, mpool_test_post)
{
    struct mpool *mp;

    merr_t   err;
    char    *buf;
    size_t   bufsz = 128 << 10;
    uint64_t logid1, logid2;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 16 * 1024, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    buf = malloc(bufsz);
    ASSERT_NE(NULL, buf);

    mdc_rw_test(lcl_ti, mp, logid1, logid2, buf, bufsz, false);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 16 * 1024, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    mdc_rw_test(lcl_ti, mp, logid1, logid2, buf, bufsz, true);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(buf);
}

MTF_DEFINE_UTEST_PREPOST(mdc_test, mdc_io_overlap, mpool_test_pre, mpool_test_post)
{
    struct mpool     *mp;
    struct mpool_mdc *mdc;

    merr_t   err;
    uint64_t logid1, logid2;
    char    *buf, *rdbuf;
    size_t   bufsz = 128 << 10, wdlen, rdlen, reclen, wdcnt, wdstart;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 16 * 1024, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    buf = malloc(bufsz);
    ASSERT_NE(NULL, buf);
    randomize_buffer(buf, bufsz, bufsz + 17);

    ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));

    wdlen = bufsz / 2;
    wdcnt = 0;
    reclen = 128;

    rdbuf = calloc(reclen, sizeof(char));
    ASSERT_NE(NULL, rdbuf);

    while (wdcnt < wdlen / reclen) {
        wdstart = wdcnt * reclen;

        err = mpool_mdc_append(mdc, buf + wdstart, reclen, false);
        if (merr_errno(err) == EFBIG)
            break;
        ASSERT_EQ(0, err);

        if (wdcnt % 51 == 0) {
            int rdcnt;
            int rc;
            int rdstart;

            rdcnt = wdcnt - 51;
            rdstart = rdcnt * reclen;

            while (rdcnt < wdcnt) {
                err = mpool_mdc_read(mdc, rdbuf, reclen, &rdlen);
                ASSERT_EQ(0, err);
                ASSERT_EQ(reclen, rdlen);

                rc = memcmp(rdbuf, buf + rdstart, reclen);
                ASSERT_EQ(0, rc);

                rdcnt = rdcnt + 1;
                rdstart = rdstart + reclen;
                memset(rdbuf, 0, reclen);
            }
        }
        wdcnt = wdcnt + 1;
    }

    ASSERT_EQ(0, mpool_mdc_close(mdc));
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mpool_mdc_close(mdc));
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(buf);
    free(rdbuf);
}

MTF_DEFINE_UTEST_PREPOST(mdc_test, mdc_io_reopen, mpool_test_pre, mpool_test_post)
{
    struct mpool     *mp;
    struct mpool_mdc *mdc;

    merr_t   err;
    uint64_t logid1, logid2;
    char    *buf, *rdbuf;
    size_t   bufsz = 128 << 10, wdlen, rdlen, reclen, wdcnt, wdstart;

    err = mpool_create(mtf_kvdb_home, &tcparams);
    ASSERT_EQ(0, err);

    err = mpool_open(mtf_kvdb_home, &trparams, O_RDWR, &mp);
    ASSERT_EQ(0, err);

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 16 * 1024, HSE_MCLASS_CAPACITY, &logid1, &logid2);
    ASSERT_EQ(0, err);

    err = mpool_mdc_commit(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    buf = malloc(bufsz);
    ASSERT_NE(NULL, buf);
    randomize_buffer(buf, bufsz, bufsz + 17);

    ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));

    wdlen = bufsz / 2;
    wdcnt = 0;
    reclen = 128;

    rdbuf = calloc(reclen, sizeof(char));
    ASSERT_NE(NULL, rdbuf);

    while (wdcnt < wdlen / reclen) {
        wdstart = wdcnt * reclen;

        err = mpool_mdc_append(mdc, buf + wdstart, reclen, false);
        if (merr_errno(err) == EFBIG)
            break;
        ASSERT_EQ(0, err);

        if (wdcnt != 0 && wdcnt % 32 == 0) {
            int rdcnt;
            int rc;
            int rdstart;

            ASSERT_EQ(0, mpool_mdc_close(mdc));
            ASSERT_EQ(0, err);

            ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));
            ASSERT_EQ(0, err);

            rdcnt = 0;
            rdstart = rdcnt * reclen;

            while (rdcnt < wdcnt) {
                err = mpool_mdc_read(mdc, rdbuf, reclen, &rdlen);
                ASSERT_EQ(0, err);
                ASSERT_EQ(reclen, rdlen);

                rc = memcmp(rdbuf, buf + rdstart, reclen);
                ASSERT_EQ(0, rc);

                rdcnt = rdcnt + 1;
                rdstart = rdstart + reclen;
                memset(rdbuf, 0, reclen);
            }
        }
        wdcnt = wdcnt + 1;
    }

    ASSERT_EQ(0, mpool_mdc_close(mdc));
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mpool_mdc_open(mp, logid1, logid2, false, &mdc));
    ASSERT_EQ(0, err);

    ASSERT_EQ(0, mpool_mdc_close(mdc));
    ASSERT_EQ(0, err);

    err = mpool_mdc_delete(mp, logid1, logid2);
    ASSERT_EQ(0, err);

    err = mpool_close(mp);
    ASSERT_EQ(0, err);

    mpool_destroy(mtf_kvdb_home, &tdparams);

    free(buf);
    free(rdbuf);
}
MTF_END_UTEST_COLLECTION(mdc_test);
