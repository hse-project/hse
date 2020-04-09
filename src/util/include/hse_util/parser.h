/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PARSER_H
#define HSE_PLATFORM_PARSER_H

#include <hse_util/inttypes.h>

typedef struct {
    const char *from;
    const char *to;
} substring_t;

struct match_token {
    s32         token;
    const char *pattern;
};

typedef struct match_token match_table_t[];

/**
 * match_token(): - Find a token and optional arg in a string
 * @str:   string to examine for token/argument pairs
 * @table: array of struct match_token's enumerating the allowed option tokens
 * @arg:   pointer to &substring_t element
 *
 * The array @table must be terminated with a struct match_token whose
 * @pattern is set to NULL. This function is nearly identical to that from
 * the Linux kernel except that only one substring_t is matched. The Linux
 * kernel's version can match more than one but that facility is not used by
 * the rest of the kernel and only works at all in a very limited fashion.
 */
int
match_token(const char *str, const match_table_t table, substring_t *arg);

/**
 * match_int(): - scan substring_t for an integer value
 * @substr: substring_t to be scanned
 * @result: resulting integer on success
 *
 * Attempts to parse the &substring_t @s as an integer. On success it sets
 * @result to the integer represented by the string and returns 0.
 *
 * On failure:
 *
 *   -ENOMEM if an allocation error occurred
 *   -EINVAL if the character sequence does not represent a valid integer
 *   -ERANGE if the parsed integer is out of range
 */
int
match_int(substring_t *substr, int *result);

/**
 * match_octal(): - scan substring_t as octal for an integer value
 * @substr: substring_t to be scanned
 * @result: resulting integer on success
 *
 * Attempts to parse the &substring_t @s as an octal integer. On success it
 * sets @result to the integer represented by the string and returns 0.
 *
 * On failure:
 *
 *   -ENOMEM if an allocation error occurred
 *   -EINVAL if the character sequence does not represent a valid integer
 *   -ERANGE if the parsed integer is out of range
 */
int
match_octal(substring_t *substr, int *result);

/**
 * match_hex(): - scan substring_t as hex for an integer value
 * @substr: substring_t to be scanned
 * @result: resulting integer on success
 *
 * Attempts to parse the &substring_t @s as a hexadecimal integer. On success
 * it sets @result to the integer represented by the string and returns 0.
 *
 * On failure:
 *
 *   -ENOMEM if an allocation error occurred
 *   -EINVAL if the character sequence does not represent a valid integer
 *   -ERANGE if the parsed integer is out of range
 */
int
match_hex(substring_t *substr, int *result);

/**
 * match_strlcpy(): - copy a substring_t into a buffer, null terminated
 * @dest:   destination buffer
 * @substr: substring_t to copied
 * @size:   size of destination buffer
 *
 * Copies at most @size-1 bytes from @substr to the destination buffer and
 * returns the actual length of @substr.
 *
 * On failure:
 *
 *   -ENOMEM if an allocation error occurred
 *   -EINVAL if the character sequence does not represent a valid integer
 *   -ERANGE if the parsed integer is out of range
 */
size_t
match_strlcpy(char *dest, const substring_t *source, size_t size);

/**
 * match_strdup(): - create a null-terminated copy of a substring_t
 * @substr: substring_t to be duplicated
 *
 * Using malloc/kmalloc, allocates a buffer, makes a null-terminated copy of
 * the &substring_t in that buffer, and returns the buffer. Null is returned
 * in the event of an allocation failure.
 */
char *
match_strdup(const substring_t *substr);

#endif /*  HSE_PLATFORM_PARSER_H */
