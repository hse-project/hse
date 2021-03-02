/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PARSER_INTERNAL_H
#define HSE_PLATFORM_PARSER_INTERNAL_H

#include <hse_util/hse_err.h>
#include <hse_util/parser.h>

/**
 * match_once: - Determines if a string matches a simple pattern
 * @str: the string to examine for presence of the pattern
 * @ptrn: the string containing the pattern
 * @matched: 0 / 1 on no-match / match
 * @val_found: 0 / 1 on no-match / match
 * @val: struct substring with beginning / end of value to read
 *
 * This function takes as input a string to be scanned and a pattern defining
 * the scan. The patterns are of the form "name" or "name=%?" where "%?" is
 * a printf()-like conversion specifier drawn from 's', 'd', 'o', 'u', and 'x'.
 *
 * If the string to be scanned does not begin with "name", then "matched" and
 * "val_found" will be set to 0 and the function returns. Repeated '%'
 * characters are treated as literals, as are any number of '=' that are not
 * followed by a conversion specifier. If there is no conversion specifier and
 * the string to be scanned is "name", then "matched" will be set to 1 and
 * "val_found" set to 0.
 *
 * If the pattern has a conversion specifier, then for the 'd', 'o', 'u', and
 * 'x' cases the portion of string to be scanned after the '=' will be
 * processed to determine if it is a valid decimal, octal, unsigned decimal,
 * or hexadecimal number respectively. If not then "matched" and "val_found"
 * will be set to 0 and the function returns. If so, then "matched" and
 * "val_found" will be set to 1 and val.ss_begin will be set to the first
 * byte of the numeric string and val.ss_end will be set to the byte following
 * the numeric string.
 *
 * In the 's' case, then "matched" and "val_found" will be set to 1 and
 * val.ss_begin will be set to the first byte of the string and val.ss_end
 * will be set to the byte after the string. There may be a non-negative
 * integer between the '%' and the 's in the conversion specifier in which
 * case the maximum length of the "val.ss_begin"/"val.ss_end" string is
 * capped to that length.
 *
 * This function is similar to the match_once() function in linux/lib/parser.c
 * but has (believe it or not) simpler semantics that are nonetheless
 * sufficient to satisfy all uses of match_token() in the linux kernel.
 */

void
match_once(const char *str, const char *ptrn, u32 *matched, u32 *val_found, substring_t *val);

/**
 * match_number: scan an integer number in the given base from a substring_t
 * @substr: substring to be scanned
 * @result: resulting integer on success
 * @base:   base to use when converting string
 *
 * The character sequence defined by @substr is parsed for an integer value
 * in terms of @base. If it a valid result is obtained, it is placed in the
 * location @result and 0 is returned. Unlike the Linux kernel version of this
 * function, the character sequence must be parseable as an integer value in
 * its entirety - i.e., it doesn't stop forming the integer when it sees a
 * character that is invalid in the given base.
 *
 * On failure:
 *
 *   -ENOMEM if an allocation error occurred
 *   -EINVAL if the character sequence does not represent a valid integer
 *           in the given base
 *   -ERANGE if the parsed integer is out of range of the type &int
 *
 */
int
match_number(substring_t *substr, int *result, int base);

#endif /*  HSE_PLATFORM_PARSER_INTERNAL_H */
