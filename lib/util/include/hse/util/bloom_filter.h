/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_PLATFORM_BLOOM_FILTER_H
#define HSE_PLATFORM_BLOOM_FILTER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/param.h>

#include <hse/util/arch.h>
#include <hse/util/assert.h>
#include <hse/util/compiler.h>

#define BYTE_SHIFT (3)

struct bf_bithash_desc {
    uint32_t bhd_bits_per_elt;
    uint32_t bhd_num_hashes;
};

struct bloom_filter {
    uint8_t *bf_bitmap;
    uint32_t bf_bitmapsz;
    uint32_t bf_modulus;
    uint32_t bf_n_hashes;
    uint32_t bf_bktshift;
    uint32_t bf_bktmask;
    uint32_t bf_rotl;
};

struct bloom_filter_stats {
    uint64_t bfs_lookup_cnt;
    uint64_t bfs_hit_cnt;
    uint64_t bfs_no_hit_cnt;
    uint64_t bfs_hit_failed_cnt;
    uint32_t bfs_ver;
    uint32_t bfs_filter_hashes;
    uint32_t bfs_filter_bits;
};

static HSE_ALWAYS_INLINE uint64_t
bf_rotl(const uint64_t x, uint32_t k)
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
bf_hash2bkt(uint64_t hash, uint32_t modulus, uint32_t bktshift)
{
    size_t bit, bkt;

    bit = (uint32_t)(hash + (hash >> 32)) % modulus;
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
static HSE_ALWAYS_INLINE uint32_t
bf_hash2bit(uint64_t *hashp, uint32_t rotl, uint32_t mask)
{
    uint64_t hash = *hashp;

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
bf_lookup(uint64_t hash, const uint8_t *bitmap, int32_t n, uint32_t rotl, uint32_t mask)
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
bf_populate(const struct bloom_filter *bf, uint64_t hash)
{
    uint8_t *bitmap = bf->bf_bitmap;
    uint32_t mask = bf->bf_bktmask;
    uint32_t rotl = bf->bf_rotl;
    int32_t n = bf->bf_n_hashes;

    bitmap += bf_hash2bkt(hash, bf->bf_modulus, bf->bf_bktshift);

    while (n-- > 0) {
        const uint32_t bit = bf_hash2bit(&hash, rotl, mask);

        setbit(bitmap, bit);
    }
}

struct bf_bithash_desc
bf_compute_bithash_est(uint32_t probability);

uint32_t
bf_size_estimate(struct bf_bithash_desc desc, uint32_t num_elmnts);

uint32_t
bf_element_estimate(struct bf_bithash_desc desc, size_t size_in_bytes);

void
bf_filter_init(
    struct bloom_filter *  filter,
    struct bf_bithash_desc desc,
    uint32_t                    exp_elmts,
    uint8_t *                   storage,
    size_t                 storage_sz);

void
bf_filter_insert_by_hash(struct bloom_filter *filter, uint64_t hash);

void
bf_filter_insert_by_hashv(struct bloom_filter *filter, uint64_t *hashv, uint32_t len);

#endif
