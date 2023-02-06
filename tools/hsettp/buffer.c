/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bsd/string.h>

#include <hse/error/merr.h>

#include <hse/util/log2.h>

#include "buffer.h"

static merr_t
buffer_grow(struct buffer *const buf, const size_t needed)
{
    char *tmp;
    size_t capacity;

    INVARIANT(buf);
    INVARIANT(needed > buf->cap);

    capacity = roundup_pow_of_two(needed);

    tmp = realloc(buf->data, capacity);
    if (!tmp)
        return merr(ENOMEM);

    buf->data = tmp;
    buf->cap = capacity;

    return 0;
}

merr_t
buffer_append(struct buffer *const buf, const char *const data, const size_t data_len)
{
    size_t needed;

    if (!buf)
        return merr(EINVAL);

    if (data_len == 0)
        return 0;

    needed = buf->len + data_len;

    if (needed > buf->cap) {
        merr_t err;

        err = buffer_grow(buf, buf->cap + needed);
        if (err)
            return err;
    }

    strlcpy(buf->data + buf->len, data, buf->cap - buf->len);
    buf->len += data_len;

    return 0;
}

void
buffer_destroy(struct buffer *const buf)
{
    if (!buf)
        return;

    free(buf->data);

    memset(buf, 0, sizeof(*buf));
}

void
buffer_erase(struct buffer *const buf, const unsigned int chars)
{
    memset(buf->data + buf->len - chars, '\0', chars);
    buf->len -= chars;
}

merr_t
buffer_init(struct buffer *const buf, const size_t initial_size)
{
    const size_t adjusted = roundup_pow_of_two(initial_size);

    if (!buf || initial_size == 0)
        return merr(EINVAL);

    buf->data = malloc(adjusted);
    if (!buf->data)
        return merr(ENOMEM);

    buf->cap = adjusted;
    buf->len = 0;

    return 0;
}

merr_t
buffer_putc(struct buffer *const buf, char c)
{
    size_t available;

    if (!buf)
        return merr(EINVAL);

    available = buf->cap - buf->len;
    if (available == 0) {
        merr_t err;

        err = buffer_grow(buf, buf->cap + 1);
        if (err)
            return err;
    }

    buf->data[buf->len++] = c;

    return 0;
}

merr_t
buffer_sprintf(struct buffer *const buf, const char *const fmt, ...)
{
    int rc;
    va_list args;
    size_t available;

    if (!buf || !fmt)
        return merr(EINVAL);

    available = buf->cap - buf->len;

    va_start(args, fmt);
    rc = vsnprintf(buf->data + buf->len, available, fmt, args);
    va_end(args);
    if (rc >= available) {
        merr_t err;

        err = buffer_grow(buf, buf->cap + rc - available);
        if (err)
            return err;

        available = buf->cap - buf->len;

        va_start(args, fmt);
        rc = vsnprintf(buf->data + buf->len, available, fmt, args);
        va_end(args);
        assert(rc < buf->len + available);
    } else if (rc < 0) {
        return merr(EBADMSG);
    }

    buf->len += rc;

    return 0;
}
