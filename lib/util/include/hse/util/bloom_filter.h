/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_BLOOM_FILTER_H
#define HSE_PLATFORM_BLOOM_FILTER_H

#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/compiler.h>
#include <hse/util/inttypes.h>

#define BYTE_SHIFT (3)

struct bf_bithash_desc {
    u32 bhd_bits_per_elt;
    u32 bhd_num_hashes;
};

struct bloom_filter {
    u8 *bf_bitmap;
    u32 bf_bitmapsz;
    u32 bf_modulus;
    u32 bf_n_hashes;
    u32 bf_bktshift;
    u32 bf_bktmask;
    u32 bf_rotl;
};

struct bloom_filter_stats {
    u64 bfs_lookup_cnt;
    u64 bfs_hit_cnt;
    u64 bfs_no_hit_cnt;
    u64 bfs_hit_failed_cnt;
    u32 bfs_ver;
    u32 bfs_filter_hashes;
    u32 bfs_filter_bits;
};

static HSE_ALWAYS_INLINE u64
bf_rotl(const u64 x, u32 k)
{
    return (x << k) | (x >> (64 - k));
}

/**
 * bf_hash2bkt() - determine byte offset of bucket which contains %hash
 * @hash:       hash used to select the bucket
 * @modulus:    bit-to-bucket modulus
 * @bktshift:   number of bits per bucket
 */
static HSE_ALWAYS_INLINE size_t
bf_hash2bkt(u64 hash, u32 modulus, u32 bktshift)
{
    size_t bit, bkt;

    bit = (u32)(hash + (hash >> 32)) % modulus;
    bkt = bit >> bktshift;

    return (bkt << bktshift) >> BYTE_SHIFT;
}

/**
 * bf_hash2bit - determine bit offset of nth hash within the bucket
 * @hashp:       ptr to hash used to select the bucket (*hashp is modified)
 * @rotl:        number of bits to rotate left
 * @mask:        bucket bit mask
 *
 * Return:
 *     Returns the bit index of *hashp within the current bucket,
 *     and then advances *hashp to the next hash for the next call.
 */
static HSE_ALWAYS_INLINE u32
bf_hash2bit(u64 *hashp, u32 rotl, u32 mask)
{
    u64 hash = *hashp;

    /* Fold the upper bits into the lower bits so that subsequent
     * passes over the full hash will yield different results.
     */
    *hashp += hash >> (64 - rotl);
    *hashp = bf_rotl(hash, rotl);

    return hash & mask;
}

/**
 * bf_lookup() - check to see if hash is in bloom bucket
 * @hash:       hash used to select the bucket
 * @bitmap:     base byte address of the bucket
 * @n:          number of hashes to check
 * @rotl:       number of bits to rotate left
 * @mask:       bloom bucket bit mask
 *
 * Return:
 *     Returns %true if all n hashes have bits set in the bucket,
 *     otherwise returns %false.
 */
static HSE_ALWAYS_INLINE bool
bf_lookup(u64 hash, const u8 *bitmap, s32 n, u32 rotl, u32 mask)
{
    while (n-- > 0) {
        const uint32_t bit = bf_hash2bit(&hash, rotl, mask);

        if (!isset(bitmap, bit))
            break;
    }

    return (n < 0);
}

/**
 * bf_populate() - populate a bloom bucket with given %hash
 * @hash:       hash used to select the bucket
 *
 * Ideally we'd like to use n statistically independent hashes for the block
 * bloom, but for our use case the additional computation is infeasible.
 * Instead, we exploit properties of xxhash64 (good entropy and avalanche)
 * such that we can extract n m-bit wide random hashes from one 64-bit hash.
 * We then leverage rotl to successively rotate the hash by an odd number
 * in order to obtain additional hashes should (n*m > 64).  This appears
 * to work well in practice for small n and m.
 *
 * Previously we employed a polynomial based on the nth call (e.g.,
 * (hash >> 32) + ((hash * nth) & 0xffffffff)), but that yields a skewed
 * distribution that is noticable with small bucket sizes and power-of-two
 * modulus, as well as being more expensive to iteratively compute.
 */
static HSE_ALWAYS_INLINE void
bf_populate(const struct bloom_filter *bf, u64 hash)
{
    u8 *bitmap = bf->bf_bitmap;
    u32 mask = bf->bf_bktmask;
    u32 rotl = bf->bf_rotl;
    s32 n = bf->bf_n_hashes;

    bitmap += bf_hash2bkt(hash, bf->bf_modulus, bf->bf_bktshift);

    while (n-- > 0) {
        const uint32_t bit = bf_hash2bit(&hash, rotl, mask);

        setbit(bitmap, bit);
    }
}

struct bf_bithash_desc
bf_compute_bithash_est(u32 probability);

u32
bf_size_estimate(struct bf_bithash_desc desc, u32 num_elmnts);

u32
bf_element_estimate(struct bf_bithash_desc desc, size_t size_in_bytes);

void
bf_filter_init(
    struct bloom_filter *  filter,
    struct bf_bithash_desc desc,
    u32                    exp_elmts,
    u8 *                   storage,
    size_t                 storage_sz);

void
bf_filter_insert_by_hash(struct bloom_filter *filter, u64 hash);

void
bf_filter_insert_by_hashv(struct bloom_filter *filter, u64 *hashv, u32 len);

#endif
