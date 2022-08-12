/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PRINTBUF_H
#define HSE_PLATFORM_PRINTBUF_H

#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>

/**
 * snprintf_append - append a formatted char string to a buffer.
 * @buf:    char *, pre-allocated buffer to which the formatted string
 *              should be appended.
 * @buf_sz: size_t, allocated size of buf
 * @offset: size_t *, offset at which to append the string. This will be
 *              incremented by the length of the string.
 * @format: standard printf format string
 * @...:    variable argument list to be passed to vnsprintf
 *
 * Standard snprintf has several unfortunate characteristics that make
 * it hard to use for iteratively filling a buffer. In particular, its
 * behavior when a given write would exceed the indicated max write.
 * Instead of returning the number of characters written, ala sprintf,
 * it returns how many characters it could have written without the barrier.
 *
 * snprintf_append provides a convenient way to manage multiple iterative
 * writes to a buffer. Each write is guaranteed not to overflow the buffer
 * and the offset is automatically advanced. A write that would have
 * overflowed the buffer is stopped at the buffer's end.
 *
 * Return: The return code from vsnprintf().
 */
int
snprintf_append(char *buf, size_t buf_sz, size_t *offset, const char *format, ...) HSE_PRINTF(4, 5);

/**
 * sprintbuf - append a formatted char string to a buffer.
 * @buf:       char *, pre-allocated buffer to which the formatted string
 *                 should be appended.
 * @remainder: size_t *, number of bytes still available in the buffer.
 *                 remainder will be decremented in this function by the
 *                 number of bytes written to the buffer.
 * @offset:    size_t *, offset at which to append the string. This will be
 *                 incremented by the length of the string.
 * @format:    standard printf format string
 * @...:       variable argument list to be passed to vnsprintf
 *
 * sprintbuf strongly resembles snprintf_append in form and function. It is,
 * in fact, a wrapper around a call to snprintf_append.
 *
 * The distinction between sprintbuf and snprintf_append is that the former
 * will decrement the remainder parameter, while the latter does not. Also,
 * sprintbuf returns a void, while snprintf_append's return indicates whether
 * the buffer was exhausted.
 *
 * Returns: void.
 */
void
sprintbuf(char *buf, size_t *remainder, size_t *offset, const char *format, ...) HSE_PRINTF(4, 5);

/**
 * vsnprintf_append - append a varargs-formatted char string to a buffer.
 * @buf:       char *, pre-allocated buffer to which the formatted string
 *                 should be appended.
 * @remainder: size_t *, number of bytes still available in the buffer.
 *                 remainder will be decremented in this function by the
 *                 number of bytes written to the buffer.
 * @offset:    size_t *, offset at which to append the string. This will be
 *                 incremented by the length of the string.
 * @format:    standard printf format string
 * @args       va_list, created with va_start
 *
 * vsnprintf_append provides the underlying functionality for both
 * sprintbuf and snprintf_append. Both of those functions take a
 * variable number of arguments, format that into a va_list and call
 * vsnprintf_append.
 *
 * Return: The return code from vsnprintf().
 */
int
vsnprintf_append(char *buf, size_t buf_sz, size_t *offset, const char *format, va_list args);

/**
 * strlcpy_append() - append %src to (dst + *offsetp)
 *
 * An efficient version of snprintf_append() for simple strings.
 * (e.g., snprintf_append(dst, dstsz, &offset, "%s", src)).
 *
 * Return: The return code from strlcpy().
 */
int
strlcpy_append(char *dst, const char *src, size_t dstsz, size_t *offsetp);

/**
 * u64_to_string() - very fast u64-to-string converter (base 10)
 *
 * Return: The length of the resulting output string.
 */
int
u64_to_string(void *dst, size_t dstsz, u64 value);

/**
 * u64_append() - convert %val to a string and append to (dst + *offsetp)
 * @dst:    output buffer
 * @dstsz:  output buffer size
 * @val:    the value to be converted
 * @width:  minimum output string width
 *
 * An efficient version of snprintf_append() for simple values
 * (e.g., snprintf_append(dst, dstsz, &offset, "%*lu", width, val)).
 *
 * If width is greater than the resulting string length the output
 * string is right justified and padded with spaces on the left.
 * As a special case, if width is less than zero then a single space
 * is prepended to the resulting string.
 * Note that the output string is never truncated (if the fully
 * converted string is longer than %dstsz then %dst remains
 * undisturbed and zero is returned).
 *
 * Return: The length of the resulting output string.
 */
int
u64_append(char *dst, size_t dstsz, u64 val, int width, size_t *offsetp);

#endif /* HSE_PLATFORM_PRINTBUF_H */
