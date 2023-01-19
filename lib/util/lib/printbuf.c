/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <bsd/string.h>

#include <hse/util/compiler.h>
#include <hse/util/platform.h>

int
vsnprintf_append(char *buf, size_t buf_sz, size_t *offset, const char *format, va_list args)
{
    int cc;

    cc = vsnprintf(buf + *offset, buf_sz - *offset, format, args);

    if (cc < 0 || cc > (buf_sz - *offset))
        *offset = buf_sz;
    else
        *offset += cc;

    return cc;
}

int
snprintf_append(char *buf, size_t buf_sz, size_t *offset, const char *format, ...)
{
    int ret;
    va_list args;

    va_start(args, format);
    ret = vsnprintf_append(buf, buf_sz, offset, format, args);
    va_end(args);

    return ret;
}

/**
 * sprintbuf()
 *
 * This does an snprintf() to &buf[offset], and updates offset
 * and remainder.  No more is printed after remainder reaches 0.
 */
void
sprintbuf(char *buf, size_t *remainder, size_t *offset, const char *format, ...)
{
    va_list args;
    size_t pre_offset = *offset;
    size_t consumed;

    va_start(args, format);
    vsnprintf_append(buf, *remainder, offset, format, args);
    va_end(args);

    consumed = *offset - pre_offset;
    *remainder -= consumed;
}

int
strlcpy_append(char *dst, const char *src, size_t dstsz, size_t *offset)
{
    int cc;

    cc = strlcpy(dst + *offset, src, dstsz - *offset);

    if (cc > (dstsz - *offset))
        *offset = dstsz;
    else
        *offset += cc;

    return cc;
}

int
u64_to_string(void *dst, size_t dstsz, uint64_t value)
{
    const uint base = 10;
    char *right = dst;
    char *left;
    int len;

    if (dstsz < 21) /* max digits + 1 in 64 bits (base 10) */
        return 0;

    do {
        uint64_t tmp = value;

        value /= base;
        *right++ = '0' + tmp - value * base;
    } while (value > 0);

    len = right - (char *)dst;
    *right-- = '\000';

    left = dst;
    while (left < right) {
        char tmp = *right;

        *right-- = *left;
        *left++ = tmp;
    }

    return len;
}

int
u64_append(char *dst, size_t dstsz, uint64_t val, int width, size_t *offp)
{
    int n;

    if (*offp >= dstsz)
        return 0;

    dstsz -= *offp;
    dst += *offp;

    n = u64_to_string(dst, dstsz, val);

    if (n > 0 && n < dstsz) {
        if (width < 0)
            width = n + 1;

        if (n < width) {
            memmove(dst + width - n, dst, n + 1);
            memset(dst, ' ', width - n);
            *offp += width;
            n = width;
        } else {
            *offp += n;
        }
    }

    return n;
}
