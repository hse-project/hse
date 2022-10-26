/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UTIL_BUFFER_H
#define HSE_UTIL_BUFFER_H

#include <stddef.h>

#include <hse/error/merr.h>

#include <hse/util/compiler.h>

struct buffer {
    char *data;
    size_t len;
    size_t cap;
};

merr_t
buffer_append(struct buffer *buf, const char *data, size_t data_len);

void
buffer_destroy(struct buffer *buf);

merr_t
buffer_init(struct buffer *buf, size_t initial_size);

merr_t
buffer_putc(struct buffer *buf, char c);

merr_t
buffer_sprintf(struct buffer *buf, const char *fmt, ...) HSE_PRINTF(2, 3);

#endif
