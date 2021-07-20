/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/parse_num.h>
#include <hse_util/hse_err.h>
#include <hse_util/page.h>
#include <hse_util/page.h>
#include <hse_util/string.h>

#include <hse/hse.h>

#include <mpool/mpool.h>

#define BUF_SIZE 1024
#define BUF_CNT  512

#define ERROR_BUFFER_SIZE 256

#define MDC_TEST_MAGIC (0x12345678)

/**
 *
 * Simple
 *
 */

/**
 * The simple test is meant to only test the basics of creating,
 * opening, closing, and destroying MDCs.
 *
 * Steps:
 * 1. Create an mpool
 * 2. Open the mpool
 * 3. Create an MDC
 * 4. Open the MDC
 * 5. Close the MDC
 * 6. Cleanup
 */

merr_t
mdc_correctness_simple(const char *path)
{
    struct mpool_rparams params = {0};
    merr_t err = 0, original_err = 0;
    char   errbuf[ERROR_BUFFER_SIZE];
    u64    oid[2];

    struct mpool     *mp;
    struct mpool_mdc *mdc;
    enum mpool_mclass mclass;

    strlcpy(params.mclass[MP_MED_CAPACITY].path, path,
            sizeof(params.mclass[MP_MED_CAPACITY].path));
    /* 2. Open the mpool */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        return err;
    }

    mclass = MP_MED_CAPACITY;

    /* 3. Create an MDC */
    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 1 << 20, mclass, &oid[0], &oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_abort(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to abort MDC : %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 1 << 20, mclass, &oid[0], &oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_commit(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to commit mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    /* 4. Open the MDC */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 5. Close the MDC */
    err = mpool_mdc_close(mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* Test MDC destroy with two committed mlogs */
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    /* Test MDC destroy with two non-existent mlogs */
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (!err && merr_errno(err) != ENOENT) {
        original_err = (err ?: merr(EBUG));
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(
            stderr, "%s.%d: MDC destroy must fail with ENOENT: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    goto close_mp;

    /* 6. Cleanup */
destroy_mdc:
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
    }

close_mp:
    err = mpool_close(mp);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
    }

    return original_err;
}

/**
 *
 * Mpool Release
 *
 */

/**
 * 1. Create an mpool
 * 2. Open the mpool
 * 3. Create an MDC
 * 4. Open the MDC
 * 5. Close the MDC
 * 6. Close the mpool
 * 7. Open the mpool
 * 8. Open the MDC
 * 9. Close the MDC
 * 10. Cleanup
 */

merr_t
mdc_correctness_mp_release(const char *path)
{
    struct mpool_rparams params = {0};
    merr_t err = 0, original_err = 0;
    char   errbuf[ERROR_BUFFER_SIZE];
    u64    oid[2];

    struct mpool     *mp;
    struct mpool_mdc *mdc;
    enum mpool_mclass mclass;

    strlcpy(params.mclass[MP_MED_CAPACITY].path, path,
            sizeof(params.mclass[MP_MED_CAPACITY].path));
    /* 2. Open the mpool */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        return err;
    }

    mclass = MP_MED_CAPACITY;

    /* 3. Create an MDC */
    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 1 << 20, mclass, &oid[0], &oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_commit(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to commit mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    /* 4. Open the MDC */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 5. Close the MDC */
    err = mpool_mdc_close(mdc);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 6. Close the mpool */
    err = mpool_close(mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 7. Open the mpool */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 8. Open the MDC */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 9. Close the MDC */
    err = mpool_mdc_close(mdc);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 10. Cleanup */
    /* Destroy the MDC */
destroy_mdc:
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
    }

close_mp:
    err = mpool_close(mp);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
    }

    return original_err;
}

/**
 *
 * Multi Readers in the Same Application
 *
 */

/**
 * 1. Create a mpool
 * 2. Open the mpool RDWR
 * 3. Create an MDC
 * 4. Open MDC
 * 5. Write pattern to MDC
 * 6. Close MDC
 * 7. Open MDC (handle: mdc[0])
 * 8. Rewind mdc[0]
 * 9. Read/Verify pattern via mdc[0]
 * 10. Rewind mdc[0]
 * 11. Open the same MDC (handle: mdc[1]
 * 12. Rewind mdc[1]
 * 13. Read/Verify pattern via mdc[1]
 * 14. Cleanup
 */

int
verify_buf(char *buf_in, size_t buf_len, char val)
{
    char  buf[buf_len];
    pid_t pid = getpid();
    u8   *p, *p1;

    memset(buf, val, buf_len);

    if (memcmp(buf, buf_in, buf_len)) {
        p = (u8 *)buf;
        p1 = (u8 *)buf_in;
        fprintf(stdout, "[%d] expect %d got %d\n", pid, (int)*p, (int)*p1);
        return 1;
    }

    return 0;
}

merr_t
mdc_correctness_multi_reader_single_app(const char *path)
{
    struct mpool_rparams params = {0};
    merr_t err = 0, original_err = 0;
    int    i, rc;
    char   errbuf[ERROR_BUFFER_SIZE];
    u64    oid[2];
    char   buf[BUF_SIZE], buf_in[BUF_SIZE];
    char   largebuf[PAGE_SIZE], largebuf_in[PAGE_SIZE];
    size_t read_len;

    struct mpool     *mp;
    struct mpool_mdc *mdc[2];
    enum mpool_mclass mclass;

    strlcpy(params.mclass[MP_MED_CAPACITY].path, path,
            sizeof(params.mclass[MP_MED_CAPACITY].path));
    /* 2. Open the mpool RDWR */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        return err;
    }

    mclass = MP_MED_CAPACITY;

    /* 3. Create an MDC */
    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 1 << 20, mclass, &oid[0], &oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_commit(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to commit mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    /* 4. Open MDC */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc[0]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 5. Write pattern to MDC */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf;
        size_t sz = BUF_SIZE;
        bool   sync = false;

        if (i % 8 == 0) {
            bufp = largebuf;
            sz = PAGE_SIZE;
        }

        memset(bufp, i, sz);
        if (i % 64 == 0 || i == BUF_CNT - 1)
            sync = true;

        err = mpool_mdc_append(mdc[0], bufp, sz, sync);
        if (err) {
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to append to MDC: %s\n", __func__, __LINE__, errbuf);
            mpool_mdc_close(mdc[0]);
            goto destroy_mdc;
        }
    }

    /* Test compaction semantics */
    for (i = 0; i < 5; i++) {
        err = mpool_mdc_cstart(mdc[0]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to cstart MDC: %s\n", __func__, __LINE__, errbuf);
            goto destroy_mdc;
        }

        for (i = 0; i < BUF_CNT; i++) {
            char  *bufp = buf;
            size_t sz = BUF_SIZE;
            bool   sync = false;

            if (i % 8 == 0) {
                bufp = largebuf;
                sz = PAGE_SIZE;
            }

            memset(bufp, i, sz);
            if (i % 64 == 0 || i == BUF_CNT - 1)
                sync = true;

            err = mpool_mdc_append(mdc[0], bufp, sz, sync);
            if (err) {
                merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
                fprintf(stderr, "%s.%d: Unable to append to MDC: %s\n", __func__, __LINE__, errbuf);
                mpool_mdc_close(mdc[0]);
                goto destroy_mdc;
            }
        }

        err = mpool_mdc_cend(mdc[0]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to cend MDC: %s\n", __func__, __LINE__, errbuf);
            goto destroy_mdc;
        }
    }

    /* 6. Close MDC */
    err = mpool_mdc_close(mdc[0]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 7. Open MDC (handle: mdc[0]) */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc[0]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 8. Rewind mdc[0] */
    err = mpool_mdc_rewind(mdc[0]);
    if (err) {
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc0;
    }

    /* 9. Read/Verify pattern via mdc[0] */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf_in;
        size_t sz = BUF_SIZE;

        if (i % 8 == 0) {
            bufp = largebuf_in;
            sz = PAGE_SIZE;
        }

        memset(bufp, ~i, sz);

        err = mpool_mdc_read(mdc[0], bufp, sz, &read_len);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to read from MDC: %s\n", __func__, __LINE__, errbuf);
            goto close_mdc0;
        }

        if (sz != read_len) {
            original_err = merr(EINVAL);
            fprintf(
                stderr,
                "%s.%d: Requested size not read exp %d, got %d\n",
                __func__,
                __LINE__,
                (int)sz,
                (int)read_len);
            goto close_mdc0;
        }

        rc = verify_buf(bufp, read_len, i);
        if (rc != 0) {
            original_err = merr(EIO);
            fprintf(stderr, "%s.%d: Verify mismatch buf[%d]\n", __func__, __LINE__, i);
            err = merr(EINVAL);
            goto close_mdc0;
        }
    }

    /* 10. Rewind mdc[0] */
    err = mpool_mdc_rewind(mdc[0]);
    if (err) {
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc0;
    }

    /* 11. Open the same MDC (handle: mdc[1], like a reopen */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc0;
    }

    /* 12. Rewind mdc[1] */
    err = mpool_mdc_rewind(mdc[1]);
    if (err) {
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc1;
    }

    /* 13. Read/Verify pattern via mdc[1] */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf_in;
        size_t sz = BUF_SIZE;

        if (i % 8 == 0) {
            bufp = largebuf_in;
            sz = PAGE_SIZE;
        }

        memset(bufp, ~i, sz);

        err = mpool_mdc_read(mdc[1], bufp, sz, &read_len);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to read from MDC: %s\n", __func__, __LINE__, errbuf);
            goto close_mdc1;
        }

        if (sz != read_len) {
            original_err = merr(EINVAL);
            fprintf(
                stderr,
                "%s.%d: Requested size not read exp %d, got %d\n",
                __func__,
                __LINE__,
                (int)sz,
                (int)read_len);
            goto close_mdc1;
        }

        rc = verify_buf(bufp, read_len, i);
        if (rc != 0) {
            original_err = merr(EIO);
            fprintf(stderr, "%s.%d: Verify mismatch buf[%d]\n", __func__, __LINE__, i);
            err = merr(EINVAL);
            goto close_mdc1;
        }
    }

    /* 14. Cleanup */
close_mdc1:
    mpool_mdc_close(mdc[1]);

close_mdc0:
    mpool_mdc_close(mdc[0]);

    /* Destroy the MDC */
destroy_mdc:
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
    }

close_mp:
    err = mpool_close(mp);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
    }

    return original_err;
}

/**
 *
 * Reader then Writer
 *
 */

/**
 * 1. Create a mpool
 * 2. Open the mpool RDWR
 * 3. Create an MDC
 * 4. Open MDC
 * 5. Write pattern to MDC
 * 6. Close MDC
 * 7. Open MDC
 * 8. Rewind mdc
 * 9. Read/Verify pattern via mdc
 * 10. Rewind mdc
 * 11. Cleanup
 */

merr_t
mdc_correctness_reader_then_writer(const char *path)
{
    struct mpool_rparams params = {0};
    merr_t err = 0, original_err = 0;
    int    i, rc;
    char   errbuf[ERROR_BUFFER_SIZE];
    u64    oid[2];
    char   buf[BUF_SIZE], buf_in[BUF_SIZE];
    char   largebuf[PAGE_SIZE], largebuf_in[PAGE_SIZE];
    size_t read_len;

    struct mpool     *mp;
    struct mpool_mdc *mdc;
    enum mpool_mclass mclass;

    strlcpy(params.mclass[MP_MED_CAPACITY].path, path,
            sizeof(params.mclass[MP_MED_CAPACITY].path));
    /* 2. Open the mpool RDWR */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        return err;
    }

    mclass = MP_MED_CAPACITY;

    /* 3. Create an MDC */
    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 128 << 10, mclass, &oid[0], &oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_commit(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to commit mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    /* 4. Open MDC */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 5. Write pattern to MDC */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf;
        size_t sz = BUF_SIZE;
        bool   sync = false;

        if (i < 32) {
            bufp = largebuf;
            sz = PAGE_SIZE;
        }

        if (i == BUF_CNT - 1)
            sync = true;

        memset(bufp, i, sz);

        err = mpool_mdc_append(mdc, bufp, sz, sync);
        if (err) {
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to append to MDC: %s\n", __func__, __LINE__, errbuf);
            goto close_mdc;
        }
    }

    for (i = 0; i < 5; i++) {
        err = mpool_mdc_cstart(mdc);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to cstart MDC: %s\n", __func__, __LINE__, errbuf);
            goto destroy_mdc;
        }

        for (i = 0; i < BUF_CNT; i++) {
            char  *bufp = buf;
            size_t sz = BUF_SIZE;
            bool   sync = false;

            if (i < 32) {
                bufp = largebuf;
                sz = PAGE_SIZE;
            }

            if (i == BUF_CNT - 1)
                sync = true;

            memset(bufp, i, sz);

            err = mpool_mdc_append(mdc, bufp, sz, sync);
            if (err) {
                merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
                fprintf(stderr, "%s.%d: Unable to append to MDC: %s\n", __func__, __LINE__, errbuf);
                mpool_mdc_close(mdc);
                goto destroy_mdc;
            }
        }

        err = mpool_mdc_cend(mdc);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to cend MDC: %s\n", __func__, __LINE__, errbuf);
            goto destroy_mdc;
        }
    }

    /* 6. Close MDC */
    err = mpool_mdc_close(mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 7. Open MDC (handle: mdc) */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 8. Rewind mdc */
    err = mpool_mdc_rewind(mdc);
    if (err) {
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc;
    }

    /* 9. Read/Verify pattern via mdc */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf_in;
        size_t sz = BUF_SIZE;

        if (i < 32) {
            bufp = largebuf_in;
            sz = PAGE_SIZE;
        }

        memset(bufp, ~i, sz);

        err = mpool_mdc_read(mdc, bufp, sz, &read_len);
        if (err) {
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to read from MDC: %s\n", __func__, __LINE__, errbuf);
            goto close_mdc;
        }

        if (sz != read_len) {
            fprintf(
                stderr,
                "%s.%d: Requested size not read exp %d, got %d\n",
                __func__,
                __LINE__,
                (int)sz,
                (int)read_len);
            goto close_mdc;
        }

        rc = verify_buf(bufp, read_len, i);
        if (rc != 0) {
            fprintf(stderr, "%s.%d: Verify mismatch buf[%d]\n", __func__, __LINE__, i);
            err = merr(EINVAL);
            goto close_mdc;
        }
    }

    /* 10. Rewind mdc */
    err = mpool_mdc_rewind(mdc);
    if (err) {
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc;
    }

    /* 11. Cleanup */
close_mdc:
    mpool_mdc_close(mdc);

    /* Destroy the MDC */
destroy_mdc:
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
    }

close_mp:
    err = mpool_close(mp);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
    }

    return original_err;
}

/**
 *
 * Writer then Reader
 *
 */

/**
 * 1. Create a mpool
 * 2. Open the mpool RDWR
 * 3. Create an MDC
 * 4. Open MDC
 * 5. Write pattern to MDC (handle: mdc[0])
 * 6. Close MDC (handle: mdc[0])
 * 7. Open MDC (handle: mdc[1]), should succeed
 * 8. Rewind mdc[1]
 * 9. Read/Verify pattern via mdc[1]
 * 10. Cleanup
 */

merr_t
mdc_correctness_writer_then_reader(const char *path)
{
    struct mpool_rparams params = {0};
    merr_t err = 0, original_err = 0;
    int    i, rc;
    char   errbuf[ERROR_BUFFER_SIZE];
    u64    oid[2];
    char   buf[BUF_SIZE], buf_in[BUF_SIZE];
    char   largebuf[PAGE_SIZE], largebuf_in[PAGE_SIZE];
    size_t read_len;

    struct mpool     *mp;
    struct mpool_mdc *mdc[2];
    enum mpool_mclass mclass;

    strlcpy(params.mclass[MP_MED_CAPACITY].path, path,
            sizeof(params.mclass[MP_MED_CAPACITY].path));
    /* 2. Open the mpool RDWR */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        return err;
    }

    mclass = MP_MED_CAPACITY;

    /* 3. Create an MDC */
    err = mpool_mdc_alloc(mp, MDC_TEST_MAGIC, 1 << 20, mclass, &oid[0], &oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    err = mpool_mdc_commit(mp, oid[0], oid[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to commit mdc: %s\n", __func__, __LINE__, errbuf);
        goto close_mp;
    }

    /* 4. Open MDC */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc[0]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 5. Write pattern to MDC (handle: mdc[0]) */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf;
        size_t sz = BUF_SIZE;
        bool   sync = false;

        if (i % 8 == 0) {
            bufp = largebuf;
            sz = PAGE_SIZE;
        }

        memset(bufp, i, sz);
        if (i % 64 == 0 || i == BUF_CNT - 1)
            sync = true;

        err = mpool_mdc_append(mdc[0], bufp, sz, sync);
        if (err) {
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to append to MDC: %s\n", __func__, __LINE__, errbuf);
            mpool_mdc_close(mdc[0]);
            goto destroy_mdc;
        }
    }

    /* 6. Close MDC (handle: mdc[0]) */
    err = mpool_mdc_close(mdc[0]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }
    mdc[0] = NULL;

    /* 7. Open MDC (handle: mdc[1]), should succeed */
    err = mpool_mdc_open(mp, oid[0], oid[1], &mdc[1]);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
        goto destroy_mdc;
    }

    /* 8. Rewind mdc[1] */
    err = mpool_mdc_rewind(mdc[1]);
    if (err) {
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
        goto close_mdc1;
    }

    /* 9. Read/Verify pattern via mdc[1] */
    for (i = 0; i < BUF_CNT; i++) {
        char  *bufp = buf_in;
        size_t sz = BUF_SIZE;

        if (i % 8 == 0) {
            bufp = largebuf_in;
            sz = PAGE_SIZE;
        }

        memset(bufp, ~i, sz);

        err = mpool_mdc_read(mdc[1], bufp, sz, &read_len);
        if (err) {
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to read from MDC: %s\n", __func__, __LINE__, errbuf);
            goto close_mdc1;
        }

        if (sz != read_len) {
            fprintf(
                stderr,
                "%s.%d: Requested size not read exp %d, got %d\n",
                __func__,
                __LINE__,
                (int)sz,
                (int)read_len);
            goto close_mdc1;
        }

        rc = verify_buf(bufp, read_len, i);
        if (rc != 0) {
            fprintf(stderr, "%s.%d: Verify mismatch buf[%d]\n", __func__, __LINE__, i);
            original_err = merr(EINVAL);
            goto close_mdc1;
        }
    }

    /* 10. Cleanup */
close_mdc1:
    mpool_mdc_close(mdc[1]);

    /* Destroy the MDC */
destroy_mdc:
    err = mpool_mdc_delete(mp, oid[0], oid[1]);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
    }

close_mp:
    err = mpool_close(mp);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
    }

    return original_err;
}

/**
 *
 * Multi MDC Single App
 *
 */

/**
 * 1. Create a mpool
 * 2. Open the mpool RDWR
 * 3. Create 4 MDCs
 * 4. Open all 4 MDCs in client serialization mode
 * 5. Write different patterns to each MDC
 * 6. Close all MDCs
 * 7. Open all 4 MDCs (handles: mdc[0..3])
 * 8. Rewind MDCs
 * 9. Read/Verify patterns on all MDCs
 * 10. Cleanup
 */

merr_t
mdc_correctness_multi_mdc(const char *path)
{
    struct mpool_rparams params = {0};
    merr_t err = 0, original_err = 0;
    int    i, j, rc;
    char   errbuf[ERROR_BUFFER_SIZE];
    char   buf[BUF_SIZE], buf_in[BUF_SIZE];
    u32    mdc_cnt = 4;
    size_t read_len;

    struct oid_s {
        u64 oid[2];
    } * oid;

    struct mpool     *mp;
    struct mpool_mdc *mdc[4];
    enum mpool_mclass mclass;

    oid = calloc(mdc_cnt, sizeof(*oid));
    if (!oid) {
        perror("oid calloc");
        return merr(ENOMEM);
    }

    strlcpy(params.mclass[MP_MED_CAPACITY].path, path,
            sizeof(params.mclass[MP_MED_CAPACITY].path));
    /* 2. Open the mpool RDWR */
    err = mpool_open(NULL, &params, O_RDWR, &mp);
    if (err) {
        original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to open the mpool: %s\n", __func__, __LINE__, errbuf);
        goto freeoid;
    }

    mclass = MP_MED_CAPACITY;

    /* 3. Create <mdc_cnt> MDCs */
    for (i = 0; i < mdc_cnt; i++) {
        err = mpool_mdc_alloc(
            mp, MDC_TEST_MAGIC + i, 1 << 20, mclass, &oid[i].oid[0], &oid[i].oid[1]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to alloc mdc: %s\n", __func__, __LINE__, errbuf);
            goto freeoid;
        }

        err = mpool_mdc_commit(mp, oid[i].oid[0], oid[i].oid[1]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to commit mdc: %s\n", __func__, __LINE__, errbuf);
            goto freeoid;
        }
    }

    /* 4. Open all <mdc_cnt> MDCs */
    for (i = 0; i < mdc_cnt; i++) {
        err = mpool_mdc_open(mp, oid[i].oid[0], oid[i].oid[1], &mdc[i]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to open MDC %d: %s\n", __func__, __LINE__, i, errbuf);
            goto destroy_mdcs;
        }
    }

    /* 5. Write different patterns to each MDC */
    for (i = 0; i < mdc_cnt; i++) {
        int v;

        for (j = 0; j < BUF_CNT; j++) {

            v = (i << 4) | (j & 0xf);

            memset(buf, v, BUF_SIZE);

            err = mpool_mdc_append(mdc[i], buf, BUF_SIZE, true);
            if (err) {
                merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
                fprintf(stderr, "%s.%d: Unable to append to MDC: %s\n", __func__, __LINE__, errbuf);
                goto close_mdcs;
            }
        }
    }

    /* 6. Close all MDCs */
    for (i = 0; i < mdc_cnt; i++) {
        err = mpool_mdc_close(mdc[i]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to close MDC: %s\n", __func__, __LINE__, errbuf);
            goto destroy_mdcs;
        }

        mdc[i] = NULL;
    }

    /* 7. Open all MDCs (handles: mdc[0..<mdc_cnt>]) */
    for (i = 0; i < mdc_cnt; i++) {
        err = mpool_mdc_open(mp, oid[i].oid[0], oid[i].oid[1], &mdc[i]);
        if (err) {
            original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to open MDC: %s\n", __func__, __LINE__, errbuf);
            goto destroy_mdcs;
        }
    }

    /* 8. Rewind MDCs */
    for (i = 0; i < mdc_cnt; i++) {
        err = mpool_mdc_rewind(mdc[i]);
        if (err) {
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to rewind to MDC: %s\n", __func__, __LINE__, errbuf);
            goto close_mdcs;
        }
    }

    /* 9. Read/Verify patterns on all MDCs */
    for (j = 0; j < BUF_CNT; j++) {
        for (i = 0; i < mdc_cnt; i++) {
            int v;

            memset(buf_in, ~i, BUF_SIZE);

            err = mpool_mdc_read(mdc[i], buf_in, BUF_SIZE, &read_len);
            if (err) {
                merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
                fprintf(stderr, "%s.%d: Unable to read from MDC: %s\n", __func__, __LINE__, errbuf);
                goto close_mdcs;
            }

            if (BUF_SIZE != read_len) {
                fprintf(
                    stderr,
                    "%s.%d: Requested size not read exp %d, got %d\n",
                    __func__,
                    __LINE__,
                    (int)BUF_SIZE,
                    (int)read_len);
                goto close_mdcs;
            }

            v = (i << 4) | (j & 0xf);
            rc = verify_buf(buf_in, read_len, v);
            if (rc != 0) {
                fprintf(stderr, "%s.%d: Verify mismatch buf[%d]\n", __func__, __LINE__, i);
                fprintf(stderr, "\tmdc %d, buf %d\n", i, j);
                original_err = merr(EINVAL);
                goto close_mdcs;
            }
        }
    }

    /* 10. Cleanup */
close_mdcs:
    for (i = 0; i < mdc_cnt; i++)
        mpool_mdc_close(mdc[i]);

    /* Destroy the MDCs */
destroy_mdcs:
    for (i = 0; i < mdc_cnt; i++) {
        err = mpool_mdc_delete(mp, oid[i].oid[0], oid[i].oid[1]);
        if (err) {
            if (!original_err)
                original_err = err;
            merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
            fprintf(stderr, "%s.%d: Unable to destroy MDC: %s\n", __func__, __LINE__, errbuf);
        }
    }

freeoid:
    free(oid);

    err = mpool_close(mp);
    if (err) {
        if (!original_err)
            original_err = err;
        merr_strinfo(err, errbuf, ERROR_BUFFER_SIZE, NULL);
        fprintf(stderr, "%s.%d: Unable to close mpool: %s\n", __func__, __LINE__, errbuf);
    }

    return original_err;
}

int
main(int argc, char **argv)
{
    struct mpool_cparams cparams = {0};
    struct mpool_dparams dparams = {0};
    merr_t   err;
    uint64_t herr;
    int      tests = 0, failed = 0;
    const char *path, *progname;

    progname = strrchr(argv[0], '/');
    progname = progname ? progname + 1 : argv[0];

    herr = hse_init(NULL, 0, NULL);
    if (herr)
        return -1;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <storage_path>\n", progname);
        hse_fini();
        return -1;
    }

    path = argv[1];
    if (access(path, F_OK) == -1) {
        fprintf(stderr, "storage path %s doesn't exist\n", path);
        hse_fini();
        return -1;
    }

    strlcpy(cparams.mclass[MP_MED_CAPACITY].path, path,
            sizeof(cparams.mclass[MP_MED_CAPACITY].path));
    err = mpool_create(NULL, &cparams);
    if (err) {
        fprintf(stderr, "mpool creation at path %s failed\n", path);
        hse_fini();
        return -1;
    }

    /* Test 1 */
    tests++;
    err = mdc_correctness_simple(path);
    if (err) {
        failed++;
        fprintf(stderr, "MDC test-%d failed\n", tests);
    }

    tests++;
    err = mdc_correctness_mp_release(path);
    if (err) {
        failed++;
        fprintf(stderr, "MDC test-%d failed\n", tests);
    }

    tests++;
    err = mdc_correctness_multi_reader_single_app(path);
    if (err) {
        failed++;
        fprintf(stderr, "MDC test-%d failed\n", tests);
    }

    tests++;
    err = mdc_correctness_reader_then_writer(path);
    if (err) {
        failed++;
        fprintf(stderr, "MDC test-%d failed\n", tests);
    }

    tests++;
    err = mdc_correctness_writer_then_reader(path);
    if (err) {
        failed++;
        fprintf(stderr, "MDC test-%d failed\n", tests);
    }

    tests++;
    err = mdc_correctness_multi_mdc(path);
    if (err) {
        failed++;
        fprintf(stderr, "MDC test-%d failed\n", tests);
    }

    fprintf(stdout, "MDC correctness tests: %d/%d passed\n", tests - failed, tests);

    strlcpy(dparams.mclass[MP_MED_CAPACITY].path, path,
            sizeof(dparams.mclass[MP_MED_CAPACITY].path));
    err = mpool_destroy(NULL, &dparams);
    if (err) {
        fprintf(stderr, "mpool destroy at path %s failed\n", path);
        hse_fini();
        return -1;
    }

    hse_fini();

    return 0;
}
