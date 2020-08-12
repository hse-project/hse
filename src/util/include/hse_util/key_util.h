/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KEY_UTIL_H
#define HSE_KEY_UTIL_H

#include <hse_util/inttypes.h>
#include <hse_util/minmax.h>
#include <hse_util/assert.h>

#define KI_DLEN_MAX (22)

/**
 * struct key_immediate - compact representation of part of a key & its length
 *
 * A struct key_immediate is a compressed representation of as much of a key
 * as will fit in ki_data[]. The layout of this structure is a reflection of
 * where it will be placed within the Bonsai tree node structure.  The layout
 * of this structure should not be altered w/o careful consideration.
 *
 * @ki_data:           array of 8-byte buffers
 * @ki_dlen:           length of key data di_data[]
 * @ki_klen:           total length of the real key
 */
struct key_immediate {
    u64 ki_data[3];
    u16 ki_dlen;
    u16 ki_klen;
};

static inline u32
key_immediate_index(const struct key_immediate *imm)
{
    return imm->ki_data[0] >> 48;
}

/**
 * key_immediate_init() - Initialize key_immediate from given key & index
 * @key:       Key to delete
 * @key_len:   Key length
 * @index:     Index to use
 * @immediate: Pointer to struct key_immediate to fill out
 */
void
key_immediate_init(const void *key, size_t key_len, u16 index, struct key_immediate *immediate);

s32
key_immediate_cmp_full(const struct key_immediate *imm0, const struct key_immediate *imm1);

static __always_inline s32
key_immediate_cmp(const struct key_immediate *imm0, const struct key_immediate *imm1)
{
    if (imm0->ki_data[0] < imm1->ki_data[0])
        return -1;
    if (imm0->ki_data[0] > imm1->ki_data[0])
        return 1;

    return key_immediate_cmp_full(imm0, imm1);
}

/**
 * key_inner_cmp() - lexicographic key comparator
 * key0:        key data ptr
 * key0_len     key0 data length
 * key1:        key data ptr
 * key1_len     key0 data length
 *
 * If memcmp returns 0, then either (1) keys are equal or (2)
 * one key is a prefix of the other.  In either case returning
 * (len1 - len2) results in desired behavior:
 *
 *   len1 == len2 --> return 0 (keys are equal).
 *   len1 <  len2 --> return neg; (key1 < ken2).
 *   len1 >  len2 --> return pos (key1 > key2).
 */
static inline int
key_inner_cmp(const void *key0, int key0_len, const void *key1, int key1_len)
{
    int rc = memcmp(key0, key1, min(key0_len, key1_len));

    return rc == 0 ? key0_len - key1_len : rc;
}

static inline s32
key_full_cmp(
    const struct key_immediate *imm0,
    const void *                key0,
    const struct key_immediate *imm1,
    const void *                key1)
{
    s32 rc;

    rc = key_immediate_cmp(imm0, imm1);

    if (rc == S32_MIN)
        rc = key_inner_cmp(
            key0 + KI_DLEN_MAX, imm0->ki_klen - KI_DLEN_MAX,
            key1 + KI_DLEN_MAX, imm1->ki_klen - KI_DLEN_MAX);

    return rc;
}

/**
 * struct key_disc - key discriminator for fast key comparison
 * kdisc:   key discriminator
 *
 * kdisc is an array of integers initialized from key data such
 * they can be quickly compared to another discriminator using
 * integer comparison and yield a lexicographic comparison.
 */
struct key_disc {
    u64 kdisc[3];
};

/**
 * key_disc_init() - initialize a key discriminator
 * @key:    ptr to an array of bytes
 * @len:    key length
 * @kdisc:  key discriminator
 */
void
key_disc_init(const void *key, size_t len, struct key_disc *kdisc);

/**
 * key_disc_cmp() - key discriminator comparator
 * @lhs:    left hand side discriminator
 * @rhs:    right hand side discriminator
 *
 * Return:
 * -1:  %lhs sorts lexicographcially less than %rhs
 *  1:  %lhs sorts lexicographically greater than %rhs
 *  0:  %lhs equals %rhs
 */
static inline int
key_disc_cmp(const struct key_disc *lhs, const struct key_disc *rhs)
{
    if (lhs->kdisc[0] > rhs->kdisc[0])
        return 1;

    if (lhs->kdisc[0] < rhs->kdisc[0])
        return -1;

    if (lhs->kdisc[1] > rhs->kdisc[1])
        return 1;

    if (lhs->kdisc[1] < rhs->kdisc[1])
        return -1;

    if (lhs->kdisc[2] > rhs->kdisc[2])
        return 1;

    if (lhs->kdisc[2] < rhs->kdisc[2])
        return -1;

    return 0;
}

/**
 * memlcp() - return longest common prefix
 * @s1:     string one
 * @s2:     string two
 * @len:    max length to compare
 *
 * Return: %memlcp compares byte string %s1 to byte string %s2,
 * returning the maximum length at which they compare identical.
 */
size_t
memlcp(const void *s1, const void *s2, size_t len);

/**
 * memlcpq() - return longest common prefix within nearest quadword
 * @s1:     string one
 * @s2:     string two
 * @len:    max length to compare
 *
 * Return: %memlcp compares byte string %s1 to byte string %s2,
 * returning the maximum length (to the nearest quadword) at which
 * they compare identical.
 */
size_t
memlcpq(const void *s1, const void *s2, size_t len);

/**
 * struct key_obj - A composite key representation with a prefix and a suffix.
 * @ko_pfx:       pointer to prefix.
 * @ko_sfx:       pointer to suffix.
 * @ko_pfx_len:    length of @pfx
 * @ko_sfx_len:    length od @sfx
 */
struct key_obj {
    const void *ko_pfx;
    const void *ko_sfx;
    uint        ko_pfx_len;
    uint        ko_sfx_len;
};

static __always_inline void *
key_obj_copy(void *kbuf, size_t kbuf_sz, uint *klen, const struct key_obj *kobj)
{
    uint  copylen, keylen;
    void *tmp_kbuf = NULL;

    keylen = kobj->ko_pfx_len + kobj->ko_sfx_len;
    if (klen)
        *klen = keylen;

    copylen = min_t(uint, kbuf_sz, kobj->ko_pfx_len);
    if (likely(kbuf && kobj->ko_pfx))
        memcpy(kbuf, kobj->ko_pfx, copylen);

    if (kbuf_sz <= kobj->ko_pfx_len)
        return kbuf;

    copylen = min_t(uint, kbuf_sz - kobj->ko_pfx_len, kobj->ko_sfx_len);
    tmp_kbuf = kbuf + kobj->ko_pfx_len;
    if (likely(tmp_kbuf && kobj->ko_sfx))
        memcpy(tmp_kbuf, kobj->ko_sfx, copylen);

    return kbuf;
}

static __always_inline uint
key_obj_len(const struct key_obj *kobj)
{
    return kobj->ko_pfx_len + kobj->ko_sfx_len;
}

/**
 * key_obj_ncmp() - Compare first n bytes of key objects.
 * @ko1:    key object 1
 * @ko2:    key object 2
 * @cmplen: length to be compared
 *
 * Return value:
 *   0            : keys are equal
 *   negative int : ko1 is "less than" ko2
 *   positive int : ko1 is "greater than" ko2
 */
static __always_inline int
key_obj_ncmp(const struct key_obj *ko1, const struct key_obj *ko2, uint cmplen)
{
    uint      klen1 = key_obj_len(ko1);
    uint      klen2 = key_obj_len(ko2);
    uint      minlen = min_t(uint, klen1, klen2);
    int       len, rc, pos;
    int       limitv[3];
    const u8 *k1, *k2;

    limitv[0] = min_t(uint, ko1->ko_pfx_len, ko2->ko_pfx_len);
    limitv[1] = max_t(uint, ko1->ko_pfx_len, ko2->ko_pfx_len);
    limitv[2] = min_t(uint, minlen, cmplen);

    k1 = ko1->ko_pfx;
    k2 = ko2->ko_pfx;

    /* 1 ...
     */
    len = min_t(uint, limitv[0], limitv[2]);
    if (likely(k1 && k2)) {
        rc = memcmp(k1, k2, len);
        if (likely(rc))
            return rc;
    }

    pos = len;
    k1 = pos < ko1->ko_pfx_len ? k1 + len : ko1->ko_sfx;
    k2 = pos < ko2->ko_pfx_len ? k2 + len : ko2->ko_sfx;

    /* 2 ...
     */
    len = min_t(uint, limitv[1], limitv[2]) - len;
    if (likely(k1 && k2)) {
        rc = memcmp(k1, k2, len);
        if (likely(rc))
            return rc;
    }

    pos += len;
    k1 = pos == ko1->ko_pfx_len ? ko1->ko_sfx : k1 + len;
    k2 = pos == ko2->ko_pfx_len ? ko2->ko_sfx : k2 + len;

    /* 3 ...
     */
    len = limitv[2] - pos;
    if (likely(k1 && k2)) {
        rc = memcmp(k1, k2, len);
        if (likely(rc))
            return rc;
    }

    return (minlen < cmplen) ? klen1 - klen2 : 0;
}

static __always_inline int
key_obj_cmp(const struct key_obj *ko1, const struct key_obj *ko2)
{
    return key_obj_ncmp(ko1, ko2, UINT_MAX);
}

/*
 * Return value:
 *   0            : ko_pfx is a prefix of ko_key.
 *   negative int : ko_pfx is "less than" than ko_key
 *   positive int : ko_pfx is "greater than" ko_key
 */
static inline int
key_obj_cmp_prefix(const struct key_obj *ko_pfx, const struct key_obj *ko_key)
{
    uint klen1 = key_obj_len(ko_pfx);
    uint klen2 = key_obj_len(ko_key);

    if (likely(klen1 <= klen2))
        return key_obj_ncmp(ko_pfx, ko_key, klen1);

    return 1;
}

static __always_inline struct key_obj *
key2kobj(struct key_obj *kobj, const void *kdata, size_t klen)
{
    kobj->ko_pfx = NULL;
    kobj->ko_pfx_len = 0;
    kobj->ko_sfx = kdata;
    kobj->ko_sfx_len = klen;

    return kobj;
}

#endif
