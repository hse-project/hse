/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>

#include <hse/error/merr.h>
#include <hse/util/hash.h>
#include <hse/util/page.h>
#include <hse/util/bloom_filter.h>

MTF_BEGIN_UTEST_COLLECTION(bloom_filter_basic);

MTF_DEFINE_UTEST(bloom_filter_basic, DoesAnything)
{
    struct bf_bithash_desc desc;
    struct bloom_filter    f;
    uint8_t                bit_block[PAGE_SIZE];
    const uint             nkeys = sizeof(bit_block) / 3;

    const char *buf1 = "The cow jumped over the moon";
    const char *buf2 = "Now just wait a damp minute";
    uint64_t    val1, val2;

    desc = bf_compute_bithash_est(20000);
    bf_filter_init(&f, desc, nkeys, bit_block, sizeof(bit_block));

    val1 = hse_hash64(buf1, strlen(buf1));
    val2 = hse_hash64(buf2, strlen(buf2));
    ASSERT_NE(val1, val2);
}

MTF_DEFINE_UTEST(bloom_filter_basic, BloomParameters)
{
    struct bf_bithash_desc desc;

    uint32_t last_bpe, last_num_hashes;
    double   ratio;
    int      i;

    desc = bf_compute_bithash_est(200);
    last_bpe = desc.bhd_bits_per_elt;
    last_num_hashes = desc.bhd_num_hashes;

    for (i = 200; i < 1000000; i += 100) {
        uint32_t est_sz;

        desc = bf_compute_bithash_est(i);
        ASSERT_LE(desc.bhd_bits_per_elt, last_bpe);
        ASSERT_LE(desc.bhd_num_hashes, last_num_hashes);

        ratio = (double)desc.bhd_num_hashes / desc.bhd_bits_per_elt;

        ASSERT_TRUE(0.699 < ratio);
        ASSERT_TRUE(0.834 > ratio);

        last_bpe = desc.bhd_bits_per_elt;
        last_num_hashes = desc.bhd_num_hashes;

        est_sz = bf_size_estimate(desc, i);
        ASSERT_EQ(1 + (desc.bhd_bits_per_elt * i) / 8, est_sz);
    }
}

MTF_DEFINE_UTEST(bloom_filter_basic, Initialization)
{
    struct bf_bithash_desc desc;
    struct bloom_filter    f;
    uint8_t                bits[PAGE_SIZE * 7];
    const uint             nkeys = sizeof(bits) / 3;

    desc = bf_compute_bithash_est(20000);
    bf_filter_init(&f, desc, nkeys, bits, sizeof(bits));

    ASSERT_EQ(desc.bhd_num_hashes, f.bf_n_hashes);
    ASSERT_EQ(&bits[0], f.bf_bitmap);
    ASSERT_EQ(sizeof(bits), f.bf_bitmapsz);
    ASSERT_GE(8 * sizeof(bits), f.bf_modulus);
    ASSERT_GT(f.bf_modulus, 0);
    ASSERT_LE(f.bf_modulus, sizeof(bits) * CHAR_BIT);
    ASSERT_EQ((1u << f.bf_bktshift) - 1, f.bf_bktmask);
}

MTF_DEFINE_UTEST(bloom_filter_basic, BasicInsert)
{
    struct bf_bithash_desc desc;
    struct bloom_filter    f;
    uint8_t *              bits;
    uint32_t               n_elts;
    uint32_t               i, n, prob;
    uint64_t               hash;
    char                   buf[100];

    n_elts = 10000;

    for (prob = 1000; prob < 90000; prob += 1773) {
        uint32_t fpc = 0;
        size_t   sz;

        desc = bf_compute_bithash_est(prob);

        sz = ALIGN(n_elts * desc.bhd_bits_per_elt, PAGE_SIZE);
        bits = aligned_alloc(PAGE_SIZE, sz);
        memset(bits, 0, sz);
        ASSERT_NE(NULL, bits);

        bf_filter_init(&f, desc, n_elts, bits, sz);

        for (i = 0; i < n_elts; ++i) {
            n = sprintf(buf, "%x:%d", i, i);
            hash = hse_hash64(buf, n);
            bf_filter_insert_by_hash(&f, hash);
        }

        for (i = 0; i < n_elts; ++i) {
            const uint8_t *bitmap = bits;
            bool           hit;

            n = sprintf(buf, "%x:%d", i, i);
            hash = hse_hash64(buf, n);

            bitmap += bf_hash2bkt(hash, f.bf_modulus, f.bf_bktshift);

            hit = bf_lookup(hash, bitmap, f.bf_n_hashes, f.bf_rotl, f.bf_bktmask);
            ASSERT_TRUE(hit);

            hit = bf_lookup(~hash, bitmap, f.bf_n_hashes, f.bf_rotl, f.bf_bktmask);
            if (hit)
                ++fpc;
        }

        ASSERT_LE(fpc, (prob * n_elts) / 1000000);

        free(bits);
    }
}

MTF_DEFINE_UTEST(bloom_filter_basic, RepeatableBasic)
{
    const char *buf1 = "The cow jumped over the moon";
    const char *buf2 = "Now just wait a damp minute";
    uint64_t    val1, val2;

    val1 = hse_hash64(buf1, strlen(buf1));
    val2 = hse_hash64(buf1, strlen(buf1));
    ASSERT_EQ(val1, val2);

    val1 = hse_hash64(buf2, strlen(buf2));
    val2 = hse_hash64(buf2, strlen(buf2));
    ASSERT_EQ(val1, val2);
}

MTF_DEFINE_UTEST(bloom_filter_basic, RepeatableEmpty)
{
    const char *buf1 = "";
    uint64_t    val1, val2;

    val1 = hse_hash64(buf1, strlen(buf1));
    val2 = hse_hash64(buf1, strlen(buf1));
    ASSERT_EQ(val1, val2);
}

MTF_END_UTEST_COLLECTION(bloom_filter_basic)
