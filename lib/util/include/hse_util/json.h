/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_JSON_H
#define HSE_PLATFORM_JSON_H

#include <hse_util/printbuf.h>

/**
 * Note that a string is considered valid JSON as long as special characters
 * are escaped. This includes single quotes, double quotes, backslashes,
 * and control characters. The functions below assume that the keys and values
 * are valid JSON.
 */

/**
 * struct json_context - JSON buffer context
 * @json_buf:    target buffer
 * @json_buf_sz: size of target buffer
 * @json_offset: offset into target buffer
 * @json_depth:  current depth of JSON object
 */
struct json_context {
    char * json_buf;
    size_t json_buf_sz;
    size_t json_offset;
    u8     json_depth;
};

/**
 * json_element_start() - initializes the JSON object
 * @jc:  JSON context
 * @key: key for nested object
 *
 * Appends either "{" or "<key>:{" to the buffer based on the current
 * depth. Requires a NULL key for new contexts.
 */
void
json_element_start(struct json_context *jc, const char *key);

/**
 * vjson_element_fieldv() - handles variable arguments
 * @jc:     JSON context
 * @fields: variable argument list
 */
void
json_element_fieldv(struct json_context *jc, va_list fields);

/**
 * json_element_field() - adds key-value pairs to the JSON object
 * @jc:  JSON context
 * @...: key, format, value triple
 *
 * Appends "<key>:<value>," to the buffer. Adds quotes to string or
 * hex based values. Only accepts one key-value pair, any additioal
 * arguments are ignored. Arguments are passed to json_element_fieldv.
 */
void
json_element_field(struct json_context *jc, ...);

/**
 * json_element_list() - adds a list of values to the JSON object
 * @jc:   JSON context1
 * @key:  key for list
 * @fmt:  format specifier
 * @argc: number of elements
 * @argv: target array
 *
 * Appends "<key>:[<argv[0]>,<argv[1]>,...]," to the buffer. Supports
 * %s, %d, and %lu format specifiers. Use json_element_list_custom to
 * handle more complex formats.
 */
void
json_element_list(struct json_context *jc, const char *key, const char *fmt, int argc, void *argv);

/**
 * json_element_list_custom() - create a list with a custom format
 * @jc:   JSON context
 * @key:  key for list
 * @cb:   callback
 * @argc: number of elements
 * @argv: target array
 *
 * Supports custom formats by invoking a callback for each element.
 * The callback is given argv, an index, a buffer, and a buffer size.
 * The value written into the buffer is appended to the list.
 */
void
json_element_list_custom(
    struct json_context *jc,
    const char *         key,
    void (*cb)(const void *, int, char *, size_t),
    int   argc,
    void *argv);

/**
 * json_element_end() - terminate the JSON object
 * @jc:  JSON context
 *
 * Appends "}" to the buffer and decrements the depth.
 */
void
json_element_end(struct json_context *jc);

#endif /* HSE_PLATFORM_JSON_H */
