/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/minmax.h>
#include <hse_util/key_util.h>

void
key_immediate_init(const void *key, size_t klen, u16 index, struct key_immediate *imm)
{
    const u8 *src = key;
    u64 *     dst;

    dst = imm->ki_data;
    dst[0] = (u64)index << 48;
    dst[1] = 0;
    dst[2] = 0;

    imm->ki_dlen = KI_DLEN_MAX;
    imm->ki_klen = klen;

    if (imm->ki_dlen > imm->ki_klen)
        imm->ki_dlen = imm->ki_klen;

    switch (imm->ki_dlen) {
        default:
        case 22:
            dst[2] |= (u64)src[21] << 0; /* FALLTHROUGH */
        case 21:
            dst[2] |= (u64)src[20] << 8; /* FALLTHROUGH */
        case 20:
            dst[2] |= (u64)src[19] << 16; /* FALLTHROUGH */
        case 19:
            dst[2] |= (u64)src[18] << 24; /* FALLTHROUGH */
        case 18:
            dst[2] |= (u64)src[17] << 32; /* FALLTHROUGH */
        case 17:
            dst[2] |= (u64)src[16] << 40; /* FALLTHROUGH */
        case 16:
            dst[2] |= (u64)src[15] << 48; /* FALLTHROUGH */
        case 15:
            dst[2] |= (u64)src[14] << 56; /* FALLTHROUGH */
                                          /* Note: dst[] index change here */
        case 14:
            dst[1] |= (u64)src[13] << 0; /* FALLTHROUGH */
        case 13:
            dst[1] |= (u64)src[12] << 8; /* FALLTHROUGH */
        case 12:
            dst[1] |= (u64)src[11] << 16; /* FALLTHROUGH */
        case 11:
            dst[1] |= (u64)src[10] << 24; /* FALLTHROUGH */
        case 10:
            dst[1] |= (u64)src[9] << 32; /* FALLTHROUGH */
        case 9:
            dst[1] |= (u64)src[8] << 40; /* FALLTHROUGH */
        case 8:
            dst[1] |= (u64)src[7] << 48; /* FALLTHROUGH */
        case 7:
            dst[1] |= (u64)src[6] << 56; /* FALLTHROUGH */
                                         /* Note: dst[] index change here */
        case 6:
            dst[0] |= (u64)src[5] << 0; /* FALLTHROUGH */
        case 5:
            dst[0] |= (u64)src[4] << 8; /* FALLTHROUGH */
        case 4:
            dst[0] |= (u64)src[3] << 16; /* FALLTHROUGH */
        case 3:
            dst[0] |= (u64)src[2] << 24; /* FALLTHROUGH */
        case 2:
            dst[0] |= (u64)src[1] << 32; /* FALLTHROUGH */
        case 1:
            dst[0] |= (u64)src[0] << 40; /* FALLTHROUGH */
        case 0:
            break;
    }
}

s32
key_immediate_cmp_full(const struct key_immediate *imm0, const struct key_immediate *imm1)
{
    if (imm0->ki_data[0] < imm1->ki_data[0])
        return -1;
    if (imm0->ki_data[0] > imm1->ki_data[0])
        return 1;
    if (imm0->ki_data[1] < imm1->ki_data[1])
        return -1;
    if (imm0->ki_data[1] > imm1->ki_data[1])
        return 1;
    if (imm0->ki_data[2] < imm1->ki_data[2])
        return -1;
    if (imm0->ki_data[2] > imm1->ki_data[2])
        return 1;

    /* If there is more to compare, tell the caller by returning S32_MIN.
     * Since keys are limited to 1023 bytes at this layer, this can't
     * be a return value from this function other than in this case.
     */
    if (imm0->ki_klen > imm0->ki_dlen && imm1->ki_klen > imm1->ki_dlen)
        return S32_MIN;

    /* Otherwise, the result comes down to the key lengths. */
    return (imm0->ki_klen - imm1->ki_klen);
}

s32
key_full_cmp(
    const struct key_immediate *imm0,
    const void *                key0,
    const struct key_immediate *imm1,
    const void *                key1)
{
    s32 rc;

    rc = key_immediate_cmp(imm0, imm1);
    if (rc != S32_MIN)
        return rc;

    /* If memcmp returns 0, then either (1) keys are equal or (2)
     * one key is a prefix of the other.  In either case returning
     * len1-len2 results in desired behavior:
     *
     *   imm0->ki_klen == imm1->ki_klen --> return 0 (keys are equal).
     *   imm0->ki_klen <  imm1->ki_klen --> return neg; (key1 < ken2).
     *   imm0->ki_klen >  imm1->ki_klen --> return pos (key1 > key2).
     *
     * Note that we skip over most of the bytes (i.e., skip) that
     * key_immediate_cmp() compared, while retaining the 8-byte
     * alignment of the key pointers (see key_immediate_init()).
     */
    rc = memcmp(
        key0 + KI_DLEN_MAX,
        key1 + KI_DLEN_MAX,
        min_t(u16, imm0->ki_klen, imm1->ki_klen) - KI_DLEN_MAX);

    return rc == 0 ? (int)(imm0->ki_klen - imm1->ki_klen) : rc;
}

void
key_disc_init(const void *key, size_t len, struct key_disc *kdisc)
{
    const u8 *src = key;
    u64 *     dst = kdisc->kdisc;

    dst[0] = 0;
    dst[1] = 0;
    dst[2] = 0;

    switch (len) {
        default:
        case 24:
            dst[2] |= (u64)src[23] << 0; /* FALLTHROUGH */
        case 23:
            dst[2] |= (u64)src[22] << 8; /* FALLTHROUGH */
        case 22:
            dst[2] |= (u64)src[21] << 16; /* FALLTHROUGH */
        case 21:
            dst[2] |= (u64)src[20] << 24; /* FALLTHROUGH */
        case 20:
            dst[2] |= (u64)src[19] << 32; /* FALLTHROUGH */
        case 19:
            dst[2] |= (u64)src[18] << 40; /* FALLTHROUGH */
        case 18:
            dst[2] |= (u64)src[17] << 48; /* FALLTHROUGH */
        case 17:
            dst[2] |= (u64)src[16] << 56; /* FALLTHROUGH */
        case 16:
            dst[1] |= (u64)src[15] << 0; /* FALLTHROUGH */
        case 15:
            dst[1] |= (u64)src[14] << 8; /* FALLTHROUGH */
        case 14:
            dst[1] |= (u64)src[13] << 16; /* FALLTHROUGH */
        case 13:
            dst[1] |= (u64)src[12] << 24; /* FALLTHROUGH */
        case 12:
            dst[1] |= (u64)src[11] << 32; /* FALLTHROUGH */
        case 11:
            dst[1] |= (u64)src[10] << 40; /* FALLTHROUGH */
        case 10:
            dst[1] |= (u64)src[9] << 48; /* FALLTHROUGH */
        case 9:
            dst[1] |= (u64)src[8] << 56; /* FALLTHROUGH */
        case 8:
            dst[0] |= (u64)src[7] << 0; /* FALLTHROUGH */
        case 7:
            dst[0] |= (u64)src[6] << 8; /* FALLTHROUGH */
        case 6:
            dst[0] |= (u64)src[5] << 16; /* FALLTHROUGH */
        case 5:
            dst[0] |= (u64)src[4] << 24; /* FALLTHROUGH */
        case 4:
            dst[0] |= (u64)src[3] << 32; /* FALLTHROUGH */
        case 3:
            dst[0] |= (u64)src[2] << 40; /* FALLTHROUGH */
        case 2:
            dst[0] |= (u64)src[1] << 48; /* FALLTHROUGH */
        case 1:
            dst[0] |= (u64)src[0] << 56; /* FALLTHROUGH */
        case 0:
            break;
    }
}

/* Bullseye doesn't play well with hand-written assembly
 */
BullseyeCoverageSaveOff

    size_t
    memlcp(const void *s1, const void *s2, size_t len)
{
    size_t rc;

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

BullseyeCoverageRestore
