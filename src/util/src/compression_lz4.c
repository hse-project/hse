/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2020 Micron Technology, Inc.  All rights reserved.
 */


#include <lz4.h>

#include <hse_util/assert.h>
#include <hse_util/event_counter.h>
#include <hse_util/compression_lz4.h>

#if ((LZ4_VERSION_MAJOR < 1) || (LZ4_VERSION_MAJOR == 1 && LZ4_VERSION_MINOR < 7))
#error "Need LZ4 1.7.0 or higher"
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
    int dst_cap;

    assert(src && dst && dst_len);

    if (ev(!src_len || !dst_capacity))
        return merr(EINVAL);

    /* LZ4 API uses ints, protect against sign and size mismatch.
     * - If src_len is too big, there's nothing we can do because this
     *   API only supports compression of a single block (i.e., no
     *   framing or streaming).
     * - If dst_capacity is too big, just reduce it to INT_MAX.  If
     *   result doesn't fit an error will be returned.
     */

    if (ev(src_len > LZ4_MAX_INPUT_SIZE))
        return merr(EINVAL);

    if (ev(dst_capacity > INT_MAX))
        dst_cap = INT_MAX;
    else
        dst_cap = (int)dst_capacity;

    len = LZ4_compress_default(src, dst, (int)src_len, dst_cap);
    if (ev(!len || len < 0 || len > dst_capacity))
        return merr(EFBIG);

    *dst_len = (uint)len;
    return 0;
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
    int dst_cap;

    assert(src && dst && dst_len);

    if (ev(!src_len || !dst_capacity))
        return merr(EINVAL);

    /* LZ4 API uses ints, protect against sign and size mismatch.
     * - If src_len is too big, there's nothing we can do because this
     *   API only supports compression of a single block (i.e., no
     *   framing or streaming).  It's also a sign that this buffer
     *   wasn't compressed with this interface.  Oops.
     * - If dst_capacity is too big, just reduce it to INT_MAX.  If
     *   result doesn't fit an error will be returned.
     */

    if (ev(src_len > INT_MAX))
        return merr(EINVAL);

    if (ev(dst_capacity > INT_MAX))
        dst_cap = INT_MAX;
    else
        dst_cap = (int)dst_capacity;

    len = LZ4_decompress_safe_partial(src, dst, (int)src_len, dst_cap, dst_cap);

    if (ev(!len || len < 0 || len > dst_capacity))
        return merr(EFBIG);

    *dst_len = (uint)len;
    return 0;
}

struct compress_ops compress_lz4_ops = {
    .cop_estimate   = compress_lz4_estimate,
    .cop_compress   = compress_lz4_compress,
    .cop_decompress = compress_lz4_decompress,
};
