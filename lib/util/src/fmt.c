/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/inttypes.h>
#include <hse_util/timing.h>

/* Append a single byte to buffer at given offset and update offset by 1.
 * If buffer is full, byte is not appended but offset is still updated.
 * This helps track how large the buffer would need to be in order to
 * fit all output data.
 */
static inline void
append_byte(void *buf, size_t buf_size, size_t *offset, char value)
{
    char *dst = buf;

    if (*offset < buf_size)
        dst[*offset] = value;

    *offset += 1;
}

/* Append string to buffer at given offset and udpate offset.
 * If buffer is too small, append as much as possible.  Offset is
 * updated as if the full string were appended.  This helps track how
 * large the buffer would need to be in order to fit all output data.
 */
static inline void
append_str(void *buf, size_t buf_size, size_t *offset, const char *str)
{
    if (!str)
        return;

    while (*str)
        append_byte(buf, buf_size, offset, *str++);
}

static bool url_unreserved[255] = {
        ['a' ... 'z'] = 1, ['A' ... 'Z'] = 1, ['0' ... '9'] = 1, ['-'] = 1,
        ['_'] = 1,         ['.'] = 1,         ['~'] = 1,
};

size_t
fmt_pe(char *dst, size_t dlen, const void *src, size_t slen)
{
    static const char hex[] = "0123456789abcdef";

    size_t soff = 0;
    size_t doff = 0;

    while (soff < slen) {

        unsigned char v = ((const unsigned char *)src)[soff++];

        if (v < NELEM(url_unreserved) && url_unreserved[v]) {
            append_byte(dst, dlen, &doff, v);
        } else {
            append_byte(dst, dlen, &doff, '%');
            append_byte(dst, dlen, &doff, hex[v >> 4]);
            append_byte(dst, dlen, &doff, hex[v & 15]);
        }
    }

    append_byte(dst, dlen, &doff, 0);

    if (doff > dlen && dlen > 0)
        ((char *)dst)[dlen - 1] = 0;

    /* Return "strlen" of desired result.
     * This is compatible with snprintf, strncpy, and strlcat.
     */
    return doff - 1;
}

size_t
fmt_hexp(
    void *      dst,
    size_t      dlen,
    const void *src,
    size_t      slen,
    const char *prefix,
    size_t      grp,
    const char *grp_sep,
    const char *suffix)

{
    static const char hex[] = "0123456789abcdef";

    size_t prefixlen, suffixlen, grpseplen;
    size_t unlimited;
    size_t soff = 0;
    size_t doff = 0;

    prefixlen = prefix ? strlen(prefix) : 0;
    suffixlen = suffix ? strlen(suffix) : 0;
    grpseplen = grp_sep ? strlen(grp_sep) : 0;

    unlimited = prefixlen + (slen * 2) + suffixlen;
    if (grp > 0 && slen > grp)
        unlimited += (slen / grp) * grpseplen;

    append_str(dst, dlen, &doff, prefix);

    while (soff < slen && dlen > doff) {
        unsigned char byte;

        if (grp && soff && (soff % grp) == 0)
            append_str(dst, dlen, &doff, grp_sep);

        byte = ((const unsigned char *)src)[soff];

        append_byte(dst, dlen, &doff, hex[byte >> 4]);
        append_byte(dst, dlen, &doff, hex[byte & 15]);

        soff += 1;
    }

    append_str(dst, dlen, &doff, suffix);
    append_byte(dst, dlen, &doff, 0);

    if (doff >= dlen && dlen > 0)
        ((char *)dst)[dlen - 1] = 0;

    /* Return "strlen" of desired result.
     * This is compatible with snprintf, strncpy, and strlcat.
     */
    return unlimited;
}

int
fmt_time(char *out, int sz, u64 ts)
{
    static const u64 billion = 1000ULL * 1000 * 1000;
    struct timespec  tspec;
    struct tm *      tmp;
    time_t           t;
    u32              ns;

    /*
     * if ts is 0, use the current localtime;
     * else if it is < 2 billion, it is a unix epoch,
     * else it is a get_realtime() converted to a u64
     */
    if (ts == 0) {
        get_realtime(&tspec);
        t = tspec.tv_sec;
        ns = tspec.tv_nsec;
    } else if (ts > 2 * billion) {
        t = ts / billion;
        ns = ts % billion;
    } else {
        t = ts;
        ns = 0;
    }

    tmp = localtime(&t);
    return snprintf(
        out,
        sz,
        "%4d-%02d-%02dT%02d:%02d:%02d.%06d",
        tmp->tm_year + 1900,
        tmp->tm_mon + 1,
        tmp->tm_mday,
        tmp->tm_hour,
        tmp->tm_min,
        tmp->tm_sec,
        ns / 1000);
}
