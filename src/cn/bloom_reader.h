/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_BLOOM_READER_H
#define HSE_KVS_CN_BLOOM_READER_H

#include <hse_util/inttypes.h>

#include <hse_ikvdb/tuple.h>

struct mpool;
struct kvs_mblk_desc;

/**
 * struct bloom_desc - a descriptor for reading data from a Bloom filter
 * @bd_blkid:       ID of mblock containing the Bloom filter
 * @bd_first_page:  offset, in pages, from start of mblock to data region
 * @bd_n_pages:     size of data region in pages
 * @bd_n_hashes:
 * @bd_n_bits:      size of bloom filter in bits
 *
 * When a kblock is opened for reading, the @bloom_hdr_omf struct is read from
 * media and the relevant information is stored in a @bloom_desc struct.
 *
 * Notes:
 *  - @bd_first_page and @bd_n_pages are in units of 4K pages.
 *    So, if @bd_first_page=2 and @bd_n_pages=3, then the Bloom
 *    filter data region occupies pages 2,3 and 4 -- which maps
 *    to bytes 2*4096 to 5*4096-1 (end of page 4).
 */
struct bloom_desc {
    u32 bd_modulus;
    u32 bd_bktshift;
    u32 bd_bktmask;
    u32 bd_n_hashes;
    u32 bd_rotl;
    u32 bd_first_page;
    u32 bd_n_pages;
    u32 bd_bktsz;
};

#define BLOOM_LOOKUP_NONE (0)
#define BLOOM_LOOKUP_MCACHE (1)
#define BLOOM_LOOKUP_BUFFER (2) /* more efficient */

/**
 * bloom_reader_buffer_lookup() -
 * @desc:       bloom descriptor
 * @buffer:     base address of bloom bitmap
 * @kt:         key/value tuple
 *
 * Return:
 * %true: a hit (key might be present)
 * %false: a miss (key definitely not present)
 */
bool
bloom_reader_buffer_lookup(const struct bloom_desc *desc, const u8 *buffer, struct kvs_ktuple *kt);

merr_t
bloom_reader_mcache_lookup(
    const struct bloom_desc *   desc,
    const struct kvs_mblk_desc *kbd,
    struct kvs_ktuple *         kt,
    bool *                      hit);

#if HSE_UNIT_TEST_MODE
/**
 * bloom_reader_filter_info() - Retrieve the characteristics of the bloom filter
 * @blm_rgn_desc:  region descriptor of kblock's Bloom filter region
 * @hash_cnt:      (output) number of hash functions
 * @modulus:       (output) hash-to-bucket modulus
 */
merr_t
bloom_reader_filter_info(struct bloom_desc *blm_rgn_desc, u32 *hash_cnt, u32 *modulus);
#endif

#endif
