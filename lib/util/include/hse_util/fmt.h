/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_FMT_H
#define HSE_PLATFORM_FMT_H

#include <hse_util/inttypes.h>

/**
 * fmt_pe - format binary data in url compatible percent-encoded form
 * @dst:     output buffer
 * @dst_len: length of output buffer
 * @src:     input data
 * @src_len: length of input data
 *
 * If @dst_len > 0, then output buffer is always null terminated.
 *
 * Return value is compatible with snprintf, strlcpy, and strncpy.
 * The return value, @n, is the "strlen" size of the string fmt_hexp()
 * tried to create.  If @n >= @dst_len, then the output is truncated.
 */
size_t
fmt_pe(void *dst, size_t dst_len, const void *src, size_t src_len);

/* Return max buffer size needed to format @len bytes of data */
static inline size_t
fmt_pe_buf_size(size_t len)
{
    return 3 * len + 1;
}


/**
 * fmt_hexp - format binary data as a null-terminated printable hex string
 * @dst:     output buffer
 * @dst_len: length of output buffer
 * @src:     input data
 * @src_len: length of input data
 * @prefix:  prefix for output string (e.g., "0x")
 * @grp:     group size (0 for no grouping)
 * @grp_sep: group separator (e.g., "-")
 * @suffix:  suffix for output string (e.g., "\n")
 *
 * If @dst_len > 0, then output buffer is always null terminated.
 *
 * Return value is compatible with snprintf, strlcpy, and strncpy.
 * The return value, @n, is the "strlen" size of the string fmt_hexp()
 * tried to create.  If @n >= @dst_len, then the output is truncated.
 *
 * Example output with @prefix="0x", @grp=4, @grp_sep="-" and @suffix="":
 *    0x656e6f706d6f630a-4154470a53474154-6e0a656c6966656b
 */
size_t
fmt_hexp(
    void *      dst,
    size_t      dst_len,
    const void *src,
    size_t      src_len,
    const char *prefix,
    size_t      grp,
    const char *grp_sep,
    const char *suffix);

static inline size_t
fmt_hex(char *dst, size_t dst_len, const void *src, size_t src_len)
{
    return fmt_hexp(dst, dst_len, src, src_len, "0x", 8, "-", "");
}

/* Return max buffer size needed to format @len bytes of data */
static inline size_t
fmt_hex_buf_size(size_t len)
{
    /* "0x" + hex_bytes + dashes + NULL */
    return 2 + 2 * len + (len / 8) + 1;
}

#endif
