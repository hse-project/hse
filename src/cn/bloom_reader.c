/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/bloom_filter.h>
#include <hse_util/bitmap.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/key_hash.h>

#include <mpool/mpool.h>

#include "bloom_reader.h"
#include "kvs_mblk_desc.h"

/* [HSE_REVISIT] bloom_filter.[ch] provides an abstracted data type for a bloom
 * filter, but does not provide for creation of a self-managed bloom filter
 * object.  This leaves it up to the client to create and manage the operation
 * of the filter.
 *
 * Moving forward, we need to have bloom filter create a self managed object
 * so that clients (such as what we see here) need not have to manage
 * the details.
 *
 * Implementing a RAM buffer based bloom object is trivial, but a generalized
 * non-buffered mcache version is trickier and would likely require hooks and
 * such in order to access random mcache pages in an mcache-agnostic manner.
 * The rub is to implement it in a way that doesn't clobber performance.
 */

merr_t
bloom_reader_mcache_lookup(
    const struct bloom_desc *   desc,
    const struct kvs_mblk_desc *kbd,
    struct kvs_ktuple *         kt,
    bool *                      hit)
{
    size_t    offsetv[1];
    void *    pagev[1];
    const u8 *bitmap;
    size_t    bkt;
    merr_t    err;

    if (!kt->kt_hash)
        kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

    bkt = bf_hash2bkt(kt->kt_hash, desc->bd_modulus, desc->bd_bktshift);
    offsetv[0] = desc->bd_first_page + bkt / PAGE_SIZE;

    err = mpool_mcache_getpages(kbd->map, 1, kbd->map_idx, offsetv, pagev);
    if (ev(err))
        return err;

    bitmap = pagev[0] + (bkt % PAGE_SIZE);

    *hit = bf_lookup(kt->kt_hash, bitmap, desc->bd_n_hashes, desc->bd_rotl, desc->bd_bktmask);

    return 0;
}

bool
bloom_reader_buffer_lookup(const struct bloom_desc *desc, const u8 *bitmap, struct kvs_ktuple *kt)
{
    if (!kt->kt_hash)
        kt->kt_hash = key_hash64(kt->kt_data, kt->kt_len);

    bitmap += bf_hash2bkt(kt->kt_hash, desc->bd_modulus, desc->bd_bktshift);

    return bf_lookup(kt->kt_hash, bitmap, desc->bd_n_hashes, desc->bd_rotl, desc->bd_bktmask);
}

merr_t
bloom_reader_filter_info(struct bloom_desc *desc, u32 *hash_cnt, u32 *modulus)
{
    *hash_cnt = desc->bd_n_hashes;
    *modulus = desc->bd_modulus;

    return 0;
}
