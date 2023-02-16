/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_TOOLS_COMMON
#define HSE_TOOLS_COMMON

/*
 * common functions for kvs tools
 */

#include <stdint.h>

#include <sys/types.h>

#include <hse/types.h>

#include <hse/util/compiler.h>

/*
 * key/value formatting
 */
size_t
fmt_data(char *out, char *in);

/*
 * globals: control the max of key and value displays in show
 * zero means unlimited, negative len means first N bytes
 * thus:
 *    kmax = 0     // show all of key, no matter the length
 *    kmax = 32    // if key is longer than 32 bytes, show first 16...last 16
 *    kmax = -8    // if key is longer than 8 bytes, show first 8...
 *
 * show / fmt attempt to intuit ascii/binary data, showing ascii as strings,
 * hex data as hex strings.  This can be defeated, showing as hex only:
 *     hexonly = 1 // show all key / value data as hex strings
 * Ascii strings are not null terminated unless zero is set:
 *     zero = 1    // append a zero (null terminator) after an ascii string
 * Hex strings are never zero padded.
 */

struct app_opts {
    int lineno;
    size_t kmax;
    size_t vmax;
    int hexonly;
    int zero;
};
extern struct app_opts Opts;

/*
 * key/value display
 */
void
show(const void *key, size_t klen, const void *val, size_t vlen, int showlen);

void
show_hex(const void *key, size_t klen, const void *val, size_t vlen, int showlen);

#endif
