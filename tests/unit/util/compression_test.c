/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/platform.h>
#include <hse/util/compression_lz4.h>
#include <hse/logging/logging.h>

#include <hse/test/mtf/framework.h>

MTF_BEGIN_UTEST_COLLECTION(compression_test);

MTF_DEFINE_UTEST(compression_test, compress)
{
    size_t srcsz, cbufsz, dbufsz;
    char *src, *src_base, *cbuf, *dbuf;
    uint cbuflen, dbuflen;
    merr_t err;
    int i;

    srcsz = HSE_KVS_VALUE_LEN_MAX + 16;
    src = src_base = malloc(srcsz);
    ASSERT_NE(NULL, src);

    dbufsz = srcsz;
    dbuf = malloc(dbufsz);
    ASSERT_NE(NULL, dbuf);

    cbufsz = compress_lz4_ops.cop_estimate(NULL, srcsz);
    ASSERT_GE(cbufsz, srcsz);

    cbuf = malloc(cbufsz);
    ASSERT_NE(NULL, cbuf);

    for (i = 0; i < srcsz; ++i)
        src[i] = i / 7;

    /* Compress the full source buffer, output to cbuf...
     */
    err = compress_lz4_ops.cop_compress(src, srcsz, cbuf, cbufsz, &cbuflen);
    if (err)
        log_errx("srcsz %zu, cbufsz %zu, cbuflen %u",
                 err, srcsz, cbufsz, cbuflen);
    ASSERT_EQ(0, err);

    memset(dbuf, 0xaa, dbufsz);

    /* Decompress the full compressed buffer, output to dbuf...
     */
    err = compress_lz4_ops.cop_decompress(cbuf, cbuflen, dbuf, dbufsz, &dbuflen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(srcsz, dbuflen);
    ASSERT_EQ(0, memcmp(src, dbuf, dbuflen));

    /* Check that we can correctly decompress sublengths near the upper
     * and lower bounds of the original uncompressed length.
     */
    for (i = 1; i < srcsz + 1; ++i) {
        memset(dbuf, 0xaa, i);

        err = compress_lz4_ops.cop_decompress(cbuf, cbuflen, dbuf, i, &dbuflen);
        if (err)
            log_errx("i %u, cbuflen %u, dbuflen %u",
                     err, i, cbuflen, dbuflen);

        ASSERT_EQ(0, err);
        ASSERT_EQ(i, dbuflen);
        ASSERT_EQ(0, memcmp(src, dbuf, i));

        if (i > 4097 && i < srcsz - 4097)
            i = srcsz - 4098;
    }

    /* Check that passing unaligned source and destination buffers and lengths
     * compress and decompress as expected.
     */
    for (i = 0; i < 32; ++i) {
        srcsz = 512 + 8 - i;

        err = compress_lz4_ops.cop_compress(src + i, srcsz, cbuf + i, cbufsz - i, &cbuflen);
        if (err)
            log_errx("srcsz %zu, cbufsz %zu, cbuflen %u",
                     err, srcsz, cbufsz - i, cbuflen);
        ASSERT_EQ(0, err);

        memset(dbuf, 0xaa, dbufsz);

        err = compress_lz4_ops.cop_decompress(cbuf + i, cbuflen, dbuf + i, (srcsz % 15) + 1, &dbuflen);
        ASSERT_EQ(0, err);
        ASSERT_EQ((srcsz % 15) + 1, dbuflen);
        ASSERT_EQ(0, memcmp(src + i, dbuf + i, dbuflen));
    }

    free(dbuf);
    free(cbuf);
    free(src_base);
}

/* A known test case that fails with versions of liblz4 prior to v1.9.2
 * that was generated via the hse-mongo connector.
 */
MTF_DEFINE_UTEST(compression_test, mongo)
{
    size_t srcsz, cbufsz, dbufsz;
    char *cbuf, *dbuf;
    uint cbuflen, dbuflen;
    merr_t err;

    char srcv[] = {
        158, 0, 0, 0, 2, 110, 115, 0, 18, 0, 0, 0, 108, 111, 99, 97,
        108, 46, 115, 116, 97, 114, 116, 117, 112, 95, 108, 111, 103, 0, 2, 105,
        100, 101, 110, 116, 0, 34, 0, 0, 0, 99, 111, 108, 108, 101, 99, 116,
        105, 111, 110, 45, 48, 45, 45, 52, 55, 49, 48, 53, 55, 56, 55, 53,
        53, 53, 57, 48, 57, 50, 53, 55, 51, 51, 0, 3, 109, 100, 0, 78,
        0, 0, 0, 2, 110, 115, 0, 18, 0, 0, 0, 108, 111, 99, 97, 108,
        46, 115, 116, 97, 114, 116, 117, 112, 95, 108, 111, 103, 0, 3, 111, 112,
        116, 105, 111, 110, 115, 0, 24, 0, 0, 0, 8, 99, 97, 112, 112, 101,
        100, 0, 1, 16, 115, 105, 122, 101, 0, 0, 0, 160, 0, 0, 4, 105,
        110, 100, 101, 120, 101, 115, 0, 5, 0, 0, 0, 0, 0, 0
    };

    srcsz = sizeof(srcv);

    dbufsz = srcsz;
    dbuf = malloc(dbufsz);
    ASSERT_NE(NULL, dbuf);

    cbufsz = compress_lz4_ops.cop_estimate(srcv, srcsz);
    ASSERT_GE(cbufsz, srcsz);

    cbuf = malloc(cbufsz);
    ASSERT_NE(NULL, cbuf);

    /* Compress the full source buffer, output to cbuf...
     */
    err = compress_lz4_ops.cop_compress(srcv, srcsz, cbuf, cbufsz, &cbuflen);
    if (err)
        log_errx("srcsz %zu, cbufsz %zu, cbuflen %u",
                 err, srcsz, cbufsz, cbuflen);
    ASSERT_EQ(0, err);

    memset(dbuf, 0xaa, dbufsz);

    /* Decompress the full compressed buffer, output to dbuf...
     */
    err = compress_lz4_ops.cop_decompress(cbuf, cbuflen, dbuf, dbufsz, &dbuflen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(srcsz, dbuflen);
    ASSERT_EQ(0, memcmp(srcv, dbuf, dbuflen));

    memset(dbuf, 0xaa, dbufsz);

    /* Decompress four bytes, output to dbuf...  This fails with lz4
     * versions below v1.9.2.
     */
    err = compress_lz4_ops.cop_decompress(cbuf, cbuflen, dbuf, 4, &dbuflen);
    ASSERT_EQ(0, err);
    ASSERT_EQ(4, dbuflen);
    ASSERT_EQ(0, memcmp(srcv, dbuf, dbuflen));

    free(dbuf);
    free(cbuf);
}


MTF_END_UTEST_COLLECTION(compression_test)
