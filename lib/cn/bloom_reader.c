/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/util/page.h>
#include <hse/util/bloom_filter.h>

#include "bloom_reader.h"

/* [HSE_REVISIT] bloom_filter.[ch] provides an abstracted data type for a bloom
 * filter, but does not provide for creation of a self-managed bloom filter
 * object.  This leaves it up to the client to create and manage the operation
 * of the filter.
 *
 * Moving forward, we need to have bloom filter create a self managed object
 * so that clients (such as what we see here) need not have to manage
 * the details.
 */
bool
bloom_reader_lookup(
    const struct bloom_desc *desc,
    uint64_t                 hash)
{
    const uint8_t *bitmap = desc->bd_bitmap;
    size_t bkt;

    if (!bitmap)
        return true;

    bkt = bf_hash2bkt(hash, desc->bd_modulus, desc->bd_bktshift);

    bitmap += (bkt / PAGE_SIZE) * PAGE_SIZE + (bkt % PAGE_SIZE);

    return bf_lookup(hash, bitmap, desc->bd_n_hashes, desc->bd_rotl, desc->bd_bktmask);
}
