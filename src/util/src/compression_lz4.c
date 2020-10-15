/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/assert.h>
#include <hse_util/event_counter.h>
#include <hse_util/compression_lz4.h>

#if LZ4_VERSION_NUMBER < (10000 + 900 + 2)
#error "Need LZ4 1.9.2 or higher"
#endif

static
uint
compress_lz4_estimate(
    const void *data,
    uint        len)
{
    if (!len)
        return 0;

    /* LZ4 uses ints */
    if (len > INT_MAX)
        return 0;

    return (uint)LZ4_compressBound((int)len);
}

static
merr_t
compress_lz4_compress(
    const void *src,
    uint        src_len,
    void       *dst,
    uint        dst_capacity,
    uint       *dst_len)
{
    int len;

    /* LZ4 API uses ints, protect against sign and size mismatch.
     * - If src_len is too big, there's nothing we can do because this
     *   API only supports compression of a single block (i.e., no
     *   framing or streaming).
     * - If dst_capacity is too big it's probably a bug.
     * - If result doesn't fit an error will be returned.
     */
    assert(src && dst && dst_len);
    assert(src_len && dst_capacity);
    assert(src_len < LZ4_MAX_INPUT_SIZE && dst_capacity < INT_MAX);

    len = LZ4_compress_fast(src, dst, src_len, dst_capacity, 1);

    *dst_len = len;

    return (len < 1) ? merr(EFBIG) : 0;
}

static
merr_t
compress_lz4_decompress(
    const void *src,
    uint        src_len,
    void       *dst,
    uint        dst_capacity,
    uint       *dst_len)
{
    int len;

    /* LZ4 API uses ints, protect against sign and size mismatch.
     * - If src_len is too big, there's nothing we can do because this
     *   API only supports compression of a single block (i.e., no
     *   framing or streaming).  It's also a sign that this buffer
     *   wasn't compressed with this interface.  Oops.
     * - If dst_capacity is too big it's probably a bug.
     */
    assert(src && dst && dst_len);
    assert(src_len && dst_capacity);
    assert(src_len < INT_MAX && dst_capacity < INT_MAX);

    len = LZ4_decompress_safe_partial(src, dst, src_len, dst_capacity, dst_capacity);

    /* Decompression should not fail.  If it does you've likely got a buggy
     * version of lz4, or you've unwittingly linked against a buggy version
     * (i.e., any version prior to v1.9.2).
     */
    if (unlikely( len < 1 )) {
        hse_log(HSE_ERR "%s: slen %u, cap %u, len %d, src %p, dst %p, ver %s",
                __func__, src_len, dst_capacity, len, src, dst, LZ4_versionString());

        return merr(EFBIG);
    }

    *dst_len = len;

    return 0;
}

struct compress_ops compress_lz4_ops __read_mostly = {
    .cop_estimate   = compress_lz4_estimate,
    .cop_compress   = compress_lz4_compress,
    .cop_decompress = compress_lz4_decompress,
};
