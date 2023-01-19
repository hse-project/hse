/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_BLOOM_READER_H
#define HSE_KVS_CN_BLOOM_READER_H

#include <stdbool.h>
#include <stdint.h>

/**
 * struct bloom_desc - a descriptor for reading data from a Bloom filter
 * @bd_bitmap:      base address of bloom filter data in virtual memory
 * @bd_n_pages:     size of data region in pages
 * @bd_n_hashes:
 * @bd_first_page:  offset, in pages, from start of mblock to data region
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
    uint8_t *bd_bitmap;
    uint32_t bd_n_pages;
    uint32_t bd_modulus;
    uint32_t bd_bktshift;
    uint32_t bd_n_hashes;
    uint32_t bd_rotl;
    uint32_t bd_bktmask;
    uint32_t bd_first_page;
    uint32_t bd_bktsz;
};

/**
 * bloom_reader_lookup() -
 * @desc:  bloom descriptor
 * @hash:  hash of key to lookup
 */
bool
bloom_reader_lookup(const struct bloom_desc *desc, uint64_t hash);

#endif
