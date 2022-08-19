/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/bitmap.h>
#include <hse_util/bloom_filter.h>
#include <logging/logging.h>
#include <hse_util/page.h>

#include "bf_size2bits.i"

struct bf_prob_range {
    u32                    bfpr_min;
    u32                    bfpr_max;
    struct bf_bithash_desc bfpr_bhdesc;
};

/*
 * The following table gives the number of bits and hashes for different error
 * probability ranges. These are computed off-line to avoid floating
 * point. The min and max probability of each range are 1000000 times the
 * actual probabilities (i.e., 200000 is 20%), again to avoid floating point.
 */
static const struct bf_prob_range bf_ranges[] = {
    {
        .bfpr_min = 100,
        .bfpr_max = 200,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 20, .bhd_num_hashes = 14 }
    },
    {
        .bfpr_min = 200,
        .bfpr_max = 400,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 18, .bhd_num_hashes = 13 }
    },
    {
        .bfpr_min = 400,
        .bfpr_max = 700,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 17, .bhd_num_hashes = 12 }
    },
    {
        .bfpr_min = 700,
        .bfpr_max = 1100,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 16, .bhd_num_hashes = 12 }
    },
    {
        .bfpr_min = 1100,
        .bfpr_max = 1900,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 15, .bhd_num_hashes = 11 }
    },
    {
        .bfpr_min = 1900,
        .bfpr_max = 3100,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 14, .bhd_num_hashes = 10 }
    },
    {
        .bfpr_min = 3100,
        .bfpr_max = 5000,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 13, .bhd_num_hashes = 10 }
    },
    {
        .bfpr_min = 5000,
        .bfpr_max = 8100,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 12, .bhd_num_hashes = 9 }
    },
    {
        .bfpr_min = 8100,
        .bfpr_max = 13200,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 11, .bhd_num_hashes = 8 }
    },
    {
        .bfpr_min = 13200,
        .bfpr_max = 21400,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 10, .bhd_num_hashes = 7 }
    },
    {
        .bfpr_min = 21400,
        .bfpr_max = 34600,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 9, .bhd_num_hashes = 7 }
    },
    {
        .bfpr_min = 34600,
        .bfpr_max = 55900,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 8, .bhd_num_hashes = 6 }
    },
    {
        .bfpr_min = 55900,
        .bfpr_max = 90500,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 7, .bhd_num_hashes = 5 }
    },
    {
        .bfpr_min = 90500,
        .bfpr_max = 146300,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 6, .bhd_num_hashes = 5 }
    },
    {
        .bfpr_min = 146300,
        .bfpr_max = 200000,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 5, .bhd_num_hashes = 4 }
    },
    {
        .bfpr_min = 200000,
        .bfpr_max = 1000000,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 4, .bhd_num_hashes = 3 }
    },
    {
        .bfpr_min = 0,
        .bfpr_max = UINT_MAX,
        .bfpr_bhdesc = { .bhd_bits_per_elt = 2, .bhd_num_hashes = 1 }
    },
};

struct bf_bithash_desc
bf_compute_bithash_est(u32 probability)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(bf_ranges) - 1; ++i)
        if (probability < bf_ranges[i].bfpr_max)
            break;

    return bf_ranges[i].bfpr_bhdesc;
}

u32
bf_size_estimate(struct bf_bithash_desc desc, u32 num_elmnts)
{
    return 1 + ((num_elmnts * desc.bhd_bits_per_elt) >> BYTE_SHIFT);
}

u32
bf_element_estimate(struct bf_bithash_desc desc, size_t size_in_bytes)
{
    return (size_in_bytes << BYTE_SHIFT) / desc.bhd_bits_per_elt;
}

void
bf_filter_init(
    struct bloom_filter *  filter,
    struct bf_bithash_desc desc,
    u32                    exp_elmts,
    u8 *                   storage,
    size_t                 storage_sz)
{
    assert(IS_ALIGNED(storage_sz, PAGE_SIZE));
    assert(storage_sz >= PAGE_SIZE);

    filter->bf_n_hashes = desc.bhd_num_hashes;
    filter->bf_bktshift = BF_BKTSHIFT;
    filter->bf_bktmask = (1u << BF_BKTSHIFT) - 1;
    filter->bf_rotl = BF_ROTL;
    filter->bf_bitmap = storage;
    filter->bf_bitmapsz = storage_sz;
    filter->bf_modulus = bf_size2bits(storage_sz);

    /* We set filter bits to the largest prime not to exceed the size
     * of the bitmap (in bits) in order to obtain an optimal modulus.
     * Regardless, we will typically use all the bits in the bitmap.
     */
    assert(filter->bf_modulus < storage_sz << BYTE_SHIFT);
    assert(filter->bf_modulus > (storage_sz - PAGE_SIZE) << BYTE_SHIFT);
}

void
bf_filter_insert_by_hash(struct bloom_filter *bf, u64 hash)
{
    bf_populate(bf, hash);
}

void
bf_filter_insert_by_hashv(struct bloom_filter *bf, u64 *keyv, u32 keyc)
{
    int i;

    for (i = 0; i < keyc; ++i)
        bf_populate(bf, keyv[i]);
}
