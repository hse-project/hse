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
    size_t dlen = KI_DLEN_MAX;

    if (dlen > klen)
        dlen = klen;

    memset(imm->ki_data, 0, sizeof(imm->ki_data));
    memcpy((char *)imm->ki_data + 2, key, dlen);

    imm->ki_data[0] = be64toh(imm->ki_data[0]);
    imm->ki_data[1] = be64toh(imm->ki_data[1]);
    imm->ki_data[2] = be64toh(imm->ki_data[2]);
    imm->ki_data[3] = be64toh(imm->ki_data[3]);

    imm->ki_data[0] |= (u64)index << 48;
    imm->ki_data[3] |= (dlen << 16) | klen;
}

s32
key_immediate_cmp_full(const struct key_immediate *imm0, const struct key_immediate *imm1)
{
    int sgn;

    sgn = (imm0->ki_data[0] > imm1->ki_data[0]) - (imm0->ki_data[0] < imm1->ki_data[0]);
    if (sgn)
        return sgn;

    sgn = (imm0->ki_data[1] > imm1->ki_data[1]) - (imm0->ki_data[1] < imm1->ki_data[1]);
    if (sgn)
        return sgn;

    sgn = (imm0->ki_data[2] > imm1->ki_data[2]) - (imm0->ki_data[2] < imm1->ki_data[2]);
    if (sgn)
        return sgn;

    sgn = ((imm0->ki_data[3] >> 16) > (imm1->ki_data[3] >> 16)) -
        ((imm0->ki_data[3] >> 16) < (imm1->ki_data[3] >> 16));
    if (sgn)
        return sgn;

    /* If there is more to compare, tell the caller by returning S32_MIN.
     * Since keys are limited to 1023 bytes at this layer, this can't
     * be a return value from this function other than in this case.
     */
    if (key_imm_klen(imm0) > key_imm_dlen(imm0) &&
        key_imm_klen(imm1) > key_imm_dlen(imm1))
        return S32_MIN;

    /* Otherwise, the result comes down to the key lengths. */
    return (key_imm_klen(imm0) - key_imm_klen(imm1));
}

void
key_disc_init(const void *key, size_t len, struct key_disc *kdisc)
{
    if (len > sizeof(kdisc->kdisc))
        len = sizeof(kdisc->kdisc);

    memset(kdisc->kdisc, 0, sizeof(kdisc->kdisc));
    memcpy(kdisc->kdisc, key, len);

    kdisc->kdisc[0] = be64toh(kdisc->kdisc[0]);
    kdisc->kdisc[1] = be64toh(kdisc->kdisc[1]);
    kdisc->kdisc[2] = be64toh(kdisc->kdisc[2]);
    kdisc->kdisc[3] = be64toh(kdisc->kdisc[3]);
}

BullseyeCoverageSaveOff

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
#error memlcp() not implemented for this architecture
#endif

BullseyeCoverageRestore
