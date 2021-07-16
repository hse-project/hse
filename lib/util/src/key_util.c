/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/platform.h>
#include <hse_util/minmax.h>
#include <hse_util/key_util.h>
#include <hse/limits.h>

/* If you change the size of struct key_immediate then you'll need to update
 * key_immediate_init(), key_imm_klen(), and key_immediate_cmp_full().
 */
_Static_assert(sizeof(struct key_immediate) == 32,
               "size of key_immediate changed");

/* If HSE_KVS_COUNT_MAX becomes larger than 256 then you'll need
 * to update key_immediate_init() and key_immediate_index().
 */
_Static_assert(HSE_KVS_COUNT_MAX <= 256,
               "HSE_KVS_COUNT_MAX larger than expected");


/* This function may look expensive, but since the size of ki_data[]
 * is known, fixed, and small the optimizer won't generate any calls
 * to memset nor memcpy.
 */
void
key_immediate_init(const void *key, size_t klen, u16 index, struct key_immediate *imm)
{
    size_t dlen = klen;

    if (dlen > KI_DLEN_MAX)
        dlen = KI_DLEN_MAX;

    memset(imm, 0, sizeof(*imm));
    memcpy((char *)imm->ki_data + 1, key, dlen);

    imm->ki_data[0] = be64toh(imm->ki_data[0]);
    imm->ki_data[1] = be64toh(imm->ki_data[1]);
    imm->ki_data[2] = be64toh(imm->ki_data[2]);
    imm->ki_data[3] = be64toh(imm->ki_data[3]);

    imm->ki_data[0] |= (u64)index << 56;
    imm->ki_data[3] |= (dlen << 16) | klen;
}

s32
key_full_cmp_noinline(
    const struct key_immediate *imm0,
    const void *                key0,
    const struct key_immediate *imm1,
    const void *                key1)
{
    return key_full_cmp(imm0, key0, imm1, key1);
}


/* If you change the size of struct key_disc then you'll need
 * to update key_disc_init() and key_disc_cmp().
 */
_Static_assert(sizeof(struct key_disc) == 32,
               "size of key_disc changed");

void
key_disc_init(const void *key, size_t len, struct key_disc *kdisc)
{
    if (len > sizeof(kdisc->kdisc))
        len = sizeof(kdisc->kdisc);

    memset(kdisc, 0, sizeof(*kdisc));
    memcpy(kdisc->kdisc, key, len);

    kdisc->kdisc[0] = be64toh(kdisc->kdisc[0]);
    kdisc->kdisc[1] = be64toh(kdisc->kdisc[1]);
    kdisc->kdisc[2] = be64toh(kdisc->kdisc[2]);
    kdisc->kdisc[3] = be64toh(kdisc->kdisc[3]);
}

int
key_disc_cmp(const struct key_disc *lhs, const struct key_disc *rhs)
{
    if (lhs->kdisc[0] != rhs->kdisc[0])
        return (lhs->kdisc[0] < rhs->kdisc[0]) ? -1 : 1;

    if (lhs->kdisc[1] != rhs->kdisc[1])
        return (lhs->kdisc[1] < rhs->kdisc[1]) ? -1 : 1;

    if (lhs->kdisc[2] != rhs->kdisc[2])
        return (lhs->kdisc[2] < rhs->kdisc[2]) ? -1 : 1;

    if (lhs->kdisc[3] != rhs->kdisc[3])
        return (lhs->kdisc[3] < rhs->kdisc[3]) ? -1 : 1;

    return 0;
}
