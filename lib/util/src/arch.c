/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/arch.h>
#include <hse_util/assert.h>
#include <hse_util/compiler.h>
#include <hse_util/inttypes.h>

/* GCOV_EXCL_START */

#if __amd64__

size_t
memlcp(const void *s1, const void *s2, size_t len)
{
    size_t rc;

    /* TODO: Don't directly access rcx...
     */
    __asm__("movq   %1, %0      \n\t" /* rc = len;              */
            "cld                \n\t"
            "movq   %1, %%rcx   \n\t" /* rcx = len;             */
            "jrcxz  1f          \n\t" /* if (rcx == 0) goto 1;  */
            "repz               \n\t" /* while (rcx-- > 0 &&    */
            "cmpsb              \n\t" /*        *s1++ == *s2++) */
            "je     1f          \n\t" /* if (ZF) goto 1;        */
            "subq   %%rcx, %0   \n\t" /* rc -= rcx;             */
            "dec    %0          \n\t" /* rc -= 1;               */
            "1:                 \n\t"
            : "=rax"(rc)
            : "rdx"(len)
            : "rdi", "rsi", "rcx", "memory");

    return rc;
}

size_t
memlcpq(const void *s1, const void *s2, size_t len)
{
    size_t rc;

    /* TODO: Don't directly access rcx...
     */
    __asm__("movq   %1, %0      \n\t" /* rc = len;              */
            "shrq   $3, %0      \n\t" /* rc /= 8;               */
            "cld                \n\t"
            "movq   %0, %%rcx   \n\t" /* rcx = rc;              */
            "jrcxz  1f          \n\t" /* if (rcx == 0) goto 1;  */
            "repz               \n\t" /* while (rcx-- > 0 &&    */
            "cmpsq              \n\t" /*        *s1++ == *s2++) */
            "je     1f          \n\t" /* if (ZF) goto 1;        */
            "subq   %%rcx, %0   \n\t" /* rc -= rcx;             */
            "dec    %0          \n\t" /* rc -= 1;               */
            "1:                 \n\t"
            "shlq   $3, %0      \n\t" /* rc *= 8;               */
            : "=rax"(rc)
            : "rdx"(len)
            : "rdi", "rsi", "rdx", "rcx", "memory");

    return rc;
}

#else

size_t
memlcp(const void *s1, const void *s2, size_t len)
{
    const uint8_t *s1b = s1;
    const uint8_t *s2b = s2;
    const uint8_t *end = s1b + len;

    while (s1b < end && *s1b == *s2b++)
        ++s1b;

    return ((const char *)s1b - (const char *)s1);
}

size_t
memlcpq(const void *s1, const void *s2, size_t len)
{
    const uint64_t *s1q = s1;
    const uint64_t *s2q = s2;
    const uint64_t *end;

    if (((uintptr_t)s1q | (uintptr_t)s2q) & 0x03ul)
        return memlcp(s1, s2, len);

    end = s1q + (len / 8);

    while (s1q < end && *s1q == *s2q++)
        ++s1q;

    return ((const char *)s1q - (const char *)s1);
}
#endif

/* GCOV_EXCL_STOP */
