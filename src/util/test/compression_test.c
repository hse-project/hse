/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/compression_lz4.h>

#include <hse_ut/framework.h>

MTF_BEGIN_UTEST_COLLECTION(compression_test);

MTF_DEFINE_UTEST(compression_test, compress)
{
    size_t srcsz, cbufsz, dbufsz;
    char *src, *cbuf, *dbuf;
    uint cbuflen, dbuflen;
    merr_t err;
    int i;

    srcsz = HSE_KVS_VLEN_MAX + 1;
    src = malloc(srcsz);
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
        hse_elog(HSE_ERR "%s: srcsz %zu, cbufsz %zu, cbuflen %u: @@e",
                 err, __func__, srcsz, cbufsz, cbuflen);
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
            hse_elog(HSE_ERR "%s: i %u, cbuflen %u, dbuflen %u: @@e",
                     err, __func__, i, cbuflen, dbuflen);

        ASSERT_EQ(0, err);
        ASSERT_EQ(i, dbuflen);
        ASSERT_EQ(0, memcmp(src, dbuf, i));

        if (i > 4097 && i < srcsz - 4097)
            i = srcsz - 4098;
    }

    free(dbuf);
    free(cbuf);
    free(src);
}

MTF_END_UTEST_COLLECTION(compression_test)
