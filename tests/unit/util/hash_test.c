/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>

#include <hse/util/hash.h>
#include <hse/error/merr.h>
#include <hse/logging/logging.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(hash_test);

MTF_DEFINE_UTEST(hash_test, DoesAnything)
{
    const char *buf1 = "The cow jumped over the moon";
    const char *buf2 = "Now just wait a minute";
    uint64_t    val1, val2;

    val1 = hse_hash64(buf1, strlen(buf1));
    val2 = hse_hash64(buf2, strlen(buf2));
    ASSERT_NE(val1, val2);
}

MTF_DEFINE_UTEST(hash_test, RepeatableBasic)
{
    const char *buf1 = "Wilbur! Wilbur!";
    const char *buf2 = "Now, that just ain't right.";
    uint64_t    val1, val2;

    val1 = hse_hash64(buf1, strlen(buf1));
    val2 = hse_hash64(buf1, strlen(buf1));
    ASSERT_EQ(val1, val2);

    val1 = hse_hash64(buf2, strlen(buf2));
    val2 = hse_hash64(buf2, strlen(buf2));
    ASSERT_EQ(val1, val2);
}

MTF_DEFINE_UTEST(hash_test, RepeatableEmpty)
{
    const char *buf1 = "";
    uint64_t    val1, val2;

    val1 = hse_hash64(buf1, strlen(buf1));
    val2 = hse_hash64(buf1, strlen(buf1));
    ASSERT_EQ(val1, val2);
}

MTF_DEFINE_UTEST(hash_test, FanoutDistribution)
{
    int  d1[8] = { 0 }, d2[8] = { 0 }, d3[8] = { 0 };
    char buf[3] = { 0, 0, 1 };
    uint64_t h;
    int  i, j, n;

    n = 0;
    for (i = 0; i < 256; ++i) {
        buf[1] = i;
        for (j = 0; j < 256; ++j) {
            buf[2] = j;
            h = hse_hash64(buf, 3);
            ++d1[(h >> 0) & 7];
            ++d2[(h >> 3) & 7];
            ++d3[(h >> 6) & 7];
            ++n;
        }
    }

    /* assert distribution is within 5% tolerance */
    for (j = 0; j < 8; ++j)
        ASSERT_TRUE(abs(d1[j] - n / 8) < (n / 8 / 20));

    log_info("freq distrib for 64k prefix values / cn tree levels");

    for (i = 0; i < 8; ++i)
        log_info("%d: d1 %d  d2 %d  d3 %d", i, d1[i], d2[i], d3[i]);
}

MTF_DEFINE_UTEST(hash_test, hash_seed)
{
    const char str[] = "read me";
    size_t     sz = sizeof(str);
    uint64_t   val1, val2;
    int64_t    i;

    val1 = hse_hash64(str, sz);
    val2 = hse_hash64_seed(str, sz, 0);
    ASSERT_EQ(val1, val2);

    val1 = hse_hash64(str, sz);
    val2 = hse_hash64_seed(str, sz, 0);
    ASSERT_EQ(val1, val2);

    for (i = 0; i < 1048576; ++i) {
        val1 = hse_hash64_seed(str, sz, i);

        val2 = hse_hash64_seed(str, sz, i + 1);
        ASSERT_NE(val1, val2);

        val2 = hse_hash64_seed(str, sz, i + 2);
        ASSERT_NE(val1, val2);

        val2 = hse_hash64_seed(str, sz, i + 3);
        ASSERT_NE(val1, val2);

        val2 = hse_hash64_seed(str, sz, i + -1);
        ASSERT_NE(val1, val2);

        val2 = hse_hash64_seed(str, sz, ~i);
        ASSERT_NE(val1, val2);
    }
}

MTF_DEFINE_UTEST(hash_test, split_key_test)
{
    const char *buf1 = "The cow jumped over the moon";
    const char *buf2 = "Now just wait a darn minute. Is this sentence long enough?";
    uint64_t         single;
    int         i;

    /* buf 1 */
    single = hse_hash64(buf1, strlen(buf1));
    for (i = 0; i < strlen(buf1); i++) {
        const char *p = buf1;
        const char *s = buf1 + i;
        uint64_t    object = 0;

        object = hse_hash64v(p, i, s, strlen(buf1) - i);
        ASSERT_EQ(single, object);
    }

    /* buf 2 - length > 32 bytes */
    single = hse_hash64(buf2, strlen(buf2));
    for (i = 0; i < strlen(buf2); i++) {
        const char *p = buf2;
        const char *s = buf2 + i;
        uint64_t    object = 0;

        object = hse_hash64v(p, i, s, strlen(buf2) - i);
        ASSERT_EQ(single, object);
    }
}

MTF_END_UTEST_COLLECTION(hash_test)
