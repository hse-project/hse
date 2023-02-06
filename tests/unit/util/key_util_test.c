/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>

#include <hse/util/base.h>
#include <hse/util/key_util.h>
#include <hse/util/minmax.h>
#include <hse/util/arch.h>

MTF_BEGIN_UTEST_COLLECTION(key_util_test);

MTF_DEFINE_UTEST(key_util_test, basic)
{
    const char *         k0 = "cat";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "dog";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    key_immediate_init(k0, k0_len, 1, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);

    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_LT(res, 0);

    res = key_full_cmp_noinline(&im1, k1, &im0, k0);
    ASSERT_GT(res, 0);

    res = key_full_cmp_noinline(&im0, k0, &im0, k0);
    ASSERT_EQ(res, 0);

    res = key_full_cmp_noinline(&im1, k1, &im1, k1);
    ASSERT_EQ(res, 0);
}

MTF_DEFINE_UTEST(key_util_test, basic_key_immediate_cmp)
{
    const char *         k0 = "cat";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "dog";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    key_immediate_init(k0, k0_len, 1, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);

    res = key_immediate_cmp(&im0, &im1);
    ASSERT_LT(res, 0);

    res = key_immediate_cmp(&im1, &im0);
    ASSERT_GT(res, 0);

    res = key_immediate_cmp(&im0, &im0);
    ASSERT_EQ(res, 0);

    res = key_immediate_cmp(&im1, &im1);
    ASSERT_EQ(res, 0);
}

MTF_DEFINE_UTEST(key_util_test, check_key_immediate_index)
{
    const char *         key = "cat";
    size_t               key_len = strlen(key);
    struct key_immediate key_imm;
    uint32_t             res;
    int                  i;

    for (i = 0; i < HSE_KVS_COUNT_MAX; ++i) {
        key_immediate_init(key, key_len, i, &key_imm);
        res = key_immediate_index(&key_imm);
        ASSERT_EQ(i, res);
    }
}

uint16_t index0_array[] = {
    0, 1, 2, 3, 7, 8, 9, 12, 15, 16, 17, 31, 32, 33, 63, 64, 65,
    HSE_KVS_COUNT_MAX / 2 - 1, HSE_KVS_COUNT_MAX / 2, HSE_KVS_COUNT_MAX / 2 + 1,
    HSE_KVS_COUNT_MAX - 2, HSE_KVS_COUNT_MAX - 1
};

MTF_DEFINE_IVALUES(idx0, NELEM(index0_array), index0_array)
MTF_DEFINE_IRANGE(idx1, 0, HSE_KVS_COUNT_MAX)
MTF_DEFINE_IRANGE_STEP(idx2, 0, HSE_KVS_COUNT_MAX, 1)

MTF_DEFINE_UTEST_CP2(
    key_util_test,
    vary_index1,
    MTF_ST_IVALUES,
    uint16_t,
    idx0,
    MTF_ST_IRANGE,
    uint16_t,
    idx1)
{
    const char *         k0 = "cat";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "cat";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    if (idx0 >= HSE_KVS_COUNT_MAX) {
        printf("%s: idx0 %u >= HSE_KVS_COUNT_MAX %u\n",
               __func__, idx0, HSE_KVS_COUNT_MAX);
        ASSERT_LT(idx0, HSE_KVS_COUNT_MAX);
    }

    if (idx1 >= HSE_KVS_COUNT_MAX) {
        printf("%s: idx1 %u >= HSE_KVS_COUNT_MAX %u\n",
               __func__, idx1, HSE_KVS_COUNT_MAX);
        ASSERT_LT(idx1, HSE_KVS_COUNT_MAX);
    }

    key_immediate_init(k0, k0_len, idx0, &im0);
    key_immediate_init(k1, k1_len, idx1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);

    if (idx0 < idx1)
        ASSERT_LT(res, 0);
    else if (idx1 < idx0)
        ASSERT_GT(res, 0);
    else
        ASSERT_EQ(0, res);
}
MTF_END_CP2

MTF_DEFINE_UTEST_CP2(
    key_util_test,
    vary_index2,
    MTF_ST_IVALUES,
    uint16_t,
    idx0,
    MTF_ST_IRANGE,
    uint16_t,
    idx2)
{
    static thread_local bool inited;
    uint8_t key[KI_DLEN_MAX + 7];
    size_t klen;
    struct key_immediate im0, im1;
    int                  res;

    if (!inited) {
        srandom(time(NULL));
        inited = true;
    }

    if (idx0 >= HSE_KVS_COUNT_MAX) {
        printf("%s: idx0 %u >= HSE_KVS_COUNT_MAX %u\n",
               __func__, idx0, HSE_KVS_COUNT_MAX);
        ASSERT_LT(idx0, HSE_KVS_COUNT_MAX);
    }

    if (idx2 >= HSE_KVS_COUNT_MAX) {
        printf("%s: idx2 %u >= HSE_KVS_COUNT_MAX %u\n",
               __func__, idx2, HSE_KVS_COUNT_MAX);
        ASSERT_LT(idx2, HSE_KVS_COUNT_MAX);
    }

    /* All key bytes derive from idx0...
     */
    klen = (random() % sizeof(key)) + 1;
    memset(key, idx0, klen);

    key_immediate_init(key, klen, idx0, &im0);
    key_immediate_init(key, klen, idx2, &im1);

    res = key_full_cmp_noinline(&im0, key, &im1, key);

    if (idx0 < idx2)
        ASSERT_LT(res, 0);
    else if (idx2 < idx0)
        ASSERT_GT(res, 0);
    else
        ASSERT_EQ(0, res);

    /* All key bytes derive from idx2...
     */
    klen = (random() % sizeof(key)) + 1;
    memset(key, idx2, klen);

    key_immediate_init(key, klen, idx0, &im0);
    key_immediate_init(key, klen, idx2, &im1);

    res = key_full_cmp_noinline(&im0, key, &im1, key);

    if (idx0 < idx2)
        ASSERT_LT(res, 0);
    else if (idx2 < idx0)
        ASSERT_GT(res, 0);
    else
        ASSERT_EQ(0, res);
}
MTF_END_CP2

MTF_DEFINE_UTEST_CP2(
    key_util_test,
    vary_index3,
    MTF_ST_IRANGE,
    uint16_t,
    idx1,
    MTF_ST_IRANGE,
    uint16_t,
    idx2)
{
    const char *         k0 = "Mr. Freeze";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "Mr. Freeze";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    if (idx1 >= HSE_KVS_COUNT_MAX) {
        printf("%s: idx1 %u >= HSE_KVS_COUNT_MAX %u\n",
               __func__, idx1, HSE_KVS_COUNT_MAX);
        ASSERT_LT(idx1, HSE_KVS_COUNT_MAX);
    }

    if (idx2 >= HSE_KVS_COUNT_MAX) {
        printf("%s: idx2 %u >= HSE_KVS_COUNT_MAX %u\n",
               __func__, idx2, HSE_KVS_COUNT_MAX);
        ASSERT_LT(idx2, HSE_KVS_COUNT_MAX);
    }

    key_immediate_init(k0, k0_len, idx1, &im0);
    key_immediate_init(k1, k1_len, idx2, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);

    if (idx1 < idx2)
        ASSERT_LT(res, 0);
    else if (idx2 < idx1)
        ASSERT_GT(res, 0);
    else
        ASSERT_EQ(0, res);
}
MTF_END_CP2

MTF_DEFINE_UTEST(key_util_test, zero_length_keys)
{
    const char *         k0 = "";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    key_immediate_init(k0, k0_len, 0, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_LT(res, 0);

    key_immediate_init(k0, k0_len, 1, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_EQ(0, res);

    key_immediate_init(k0, k0_len, 2, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_GT(res, 0);
}

MTF_DEFINE_UTEST(key_util_test, dissimilar_keys)
{
    const char *         k0 = "batman";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "poison";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    key_immediate_init(k0, k0_len, 0, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_LT(res, 0);

    key_immediate_init(k0, k0_len, 1, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_LT(res, 0);

    key_immediate_init(k0, k0_len, 2, &im0);
    key_immediate_init(k1, k1_len, 1, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_GT(res, 0);
}

MTF_DEFINE_UTEST(key_util_test, key_immediate_match_length)
{
    const char *         k0 = "123testing, testing, testing";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "123testing, testing, testing, testing";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    key_immediate_init(k0, k0_len, 0, &im0);
    key_immediate_init(k1, k1_len, 0, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_LT(res, 0);
}

MTF_DEFINE_UTEST(key_util_test, key_immediate_match_lt)
{
    const char *         k0 = "123456789012345 cat";
    size_t               k0_len = strlen(k0);
    const char *         k1 = "123456789012345 dog";
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  res;

    key_immediate_init(k0, k0_len, 0, &im0);
    key_immediate_init(k1, k1_len, 0, &im1);
    res = key_full_cmp_noinline(&im0, k0, &im1, k1);
    ASSERT_LT(res, 0);
}

const char *key_arr0[] = { "a",      "xc",      "cjw",      "d8ak",      "sjw 1",
                           "dk2ckj", "a@sjewl", " &kXsWkP", "b 6%AzMbQ", "gOos9cxkLc" };
const char *key_arr1[] = { "?",      "(m",      "siQ",      "1234",      "5fiVE",
                           "  98vh", "AQ 12DK", "dXpo89mq", "wqidk1890", "ottfVsVgn1" };

MTF_DEFINE_IRANGE(karr_idx0, 0, 10)
MTF_DEFINE_IRANGE(karr_idx1, 0, 10)

int
my_memcmp(const void *key0, size_t key0_len, const void *key1, size_t key1_len)
{
    size_t cmplen = min(key0_len, key1_len);
    int    res;

    res = memcmp(key0, key1, cmplen);
    if (res != 0)
        return res;

    if (key0_len < key1_len)
        return -1;
    if (key0_len > key1_len)
        return 1;

    return 0;
}

MTF_DEFINE_UTEST_CP2(
    key_util_test,
    vary_key_data,
    MTF_ST_IRANGE,
    uint32_t,
    karr_idx0,
    MTF_ST_IRANGE,
    uint32_t,
    karr_idx1)
{
    const char *         k0 = key_arr0[karr_idx0];
    size_t               k0_len = strlen(k0);
    const char *         k1 = key_arr1[karr_idx1];
    size_t               k1_len = strlen(k1);
    struct key_immediate im0, im1;
    int                  memcmp_res, keyimmcmp_res;

    key_immediate_init(k0, k0_len, 17, &im0);
    key_immediate_init(k1, k1_len, 17, &im1);

    memcmp_res = my_memcmp(k0, k0_len, k1, k1_len);
    keyimmcmp_res = key_full_cmp_noinline(&im0, k0, &im1, k1);

    if (memcmp_res < 0)
        ASSERT_LT(keyimmcmp_res, 0);
    else if (memcmp_res > 0)
        ASSERT_GT(keyimmcmp_res, 0);
    else
        ASSERT_EQ(0, keyimmcmp_res);
}
MTF_END_CP2

MTF_DEFINE_UTEST(key_util_test, key_disc_cmp_basic)
{
    struct key_disc disc0, disc1;
    const char *    k0, *k1;
    int             rc, i;

    /* First test that equivalent strings of various lengths
     * compare equal.
     */
    k0 = k1 = "0123456701234567012345670123456701234567";

    for (i = 0; i < strlen(k0); ++i) {
        key_disc_init(k0, i + 1, &disc0);
        key_disc_init(k1, i + 1, &disc1);

        rc = key_disc_cmp(&disc0, &disc1);
        ASSERT_EQ(rc, 0);
    }

    /* Test level 0 discriminator.
     */
    k0 = "0123456x";
    k1 = "0123456y";
    key_disc_init(k0, strlen(k0), &disc0);
    key_disc_init(k1, strlen(k1), &disc1);

    rc = key_disc_cmp(&disc0, &disc1);
    ASSERT_LT(rc, 0);

    rc = key_disc_cmp(&disc1, &disc0);
    ASSERT_GT(rc, 0);

    rc = key_disc_cmp(&disc0, &disc0);
    ASSERT_EQ(rc, 0);

    rc = key_disc_cmp(&disc1, &disc1);
    ASSERT_EQ(rc, 0);

    key_disc_init(k0, strlen(k0) - 1, &disc0);
    key_disc_init(k1, strlen(k1) - 1, &disc1);

    rc = key_disc_cmp(&disc0, &disc1);
    ASSERT_EQ(rc, 0);

    /* Test level 1 discriminator.
     */
    k0 = "012345670123456x";
    k1 = "012345670123456y";
    key_disc_init(k0, strlen(k0), &disc0);
    key_disc_init(k1, strlen(k1), &disc1);

    rc = key_disc_cmp(&disc0, &disc1);
    ASSERT_LT(rc, 0);

    rc = key_disc_cmp(&disc1, &disc0);
    ASSERT_GT(rc, 0);

    rc = key_disc_cmp(&disc0, &disc0);
    ASSERT_EQ(rc, 0);

    rc = key_disc_cmp(&disc1, &disc1);
    ASSERT_EQ(rc, 0);

    key_disc_init(k0, strlen(k0) - 1, &disc0);
    key_disc_init(k1, strlen(k1) - 1, &disc1);

    rc = key_disc_cmp(&disc0, &disc1);
    ASSERT_EQ(rc, 0);

    /* Test level 2 discriminator.
     */
    k0 = "0123456701234567aaaaaaaa";
    k1 = "0123456701234567aaaaaaab";
    key_disc_init(k0, strlen(k0), &disc0);
    key_disc_init(k1, strlen(k1), &disc1);

    rc = key_disc_cmp(&disc0, &disc1);
    ASSERT_LT(rc, 0);

    rc = key_disc_cmp(&disc1, &disc0);
    ASSERT_GT(rc, 0);

    rc = key_disc_cmp(&disc0, &disc0);
    ASSERT_EQ(rc, 0);

    rc = key_disc_cmp(&disc1, &disc1);
    ASSERT_EQ(rc, 0);

    key_disc_init(k0, strlen(k0) - 1, &disc0);
    key_disc_init(k1, strlen(k1) - 1, &disc1);

    rc = key_disc_cmp(&disc0, &disc1);
    ASSERT_EQ(rc, 0);
}

/* Generate two byte strings that are identical except for the last
 * eight bytes.  memlcp() called on those strings with any length
 * under the length at which they miscompare should return the given
 * length.  memlcp() called on lengths above which they miscompare
 * should return the length at which they first miscompare.
 */
MTF_DEFINE_UTEST(key_util_test, memlcp_test)
{
    uint8_t s1[1024], s2[1024];
    size_t  i, j, lcp, max;

    srand(time(NULL));

    for (i = 0; i < 100; ++i) {
        max = rand() % (sizeof(s1) - 8);
        max += 8;

        for (j = 0; j < max; ++j)
            s1[j] = s2[j] = max + j;

        for (j = 0; j < 8; ++j)
            ++s2[max - j - 1];

        for (j = 0; j < max; ++j) {
            lcp = memlcp(s1, s2, j);

            if (j < max - 8)
                ASSERT_EQ(lcp, j);
            else
                ASSERT_EQ(lcp, max - 8);

            lcp = memlcpq(s1, s2, j);

            if (j < max - 8)
                ASSERT_EQ(lcp, j & ~7u);
            else
                ASSERT_EQ(lcp, (max - 8) & ~7u);
        }
    }
}

static void
make_key_obj(struct key_obj *ko, const void *pfx, uint plen, const void *sfx, uint slen)
{
    ko->ko_pfx = pfx;
    ko->ko_pfx_len = plen;
    ko->ko_sfx = sfx;
    ko->ko_sfx_len = slen;
}

MTF_DEFINE_UTEST(key_util_test, key_obj_cmp_test)
{
    struct key_obj ko1, ko2;
    int            rc;

    make_key_obj(&ko1, "ab", 2, "1", 1); /* ko1 = ab1 */
    make_key_obj(&ko2, "a", 1, "b2", 2); /* ko2 = ab2 */

    /* ab1 < ab2 */
    rc = key_obj_cmp(&ko1, &ko2);
    ASSERT_LT(rc, 0);

    /* ab2 > ab1 */
    rc = key_obj_cmp(&ko2, &ko1);
    ASSERT_GT(rc, 0);

    make_key_obj(&ko1, "ab", 2, "21", 2); /* ko1 = ab21 */
    /* ab21 > ab2 */
    rc = key_obj_cmp(&ko1, &ko2);
    ASSERT_GT(rc, 0);
}

MTF_DEFINE_UTEST(key_util_test, key_obj_cmp_prefix_test)
{
    struct key_obj ko1, ko2;
    int            rc;

    make_key_obj(&ko1, "a", 1, "b", 1);  /* ko1 = ab */
    make_key_obj(&ko2, "a", 1, "b2", 2); /* ko2 = ab2 */

    /* ab is a prefix of ab2 */
    rc = key_obj_cmp_prefix(&ko1, &ko2);
    ASSERT_EQ(rc, 0);
}

MTF_DEFINE_UTEST(key_util_test, key_obj_copy_test)
{
    struct key_obj ko;
    char           kbuf[4];
    uint           klen;
    int            rc;

    make_key_obj(&ko, "ab", 2, "1", 1); /* ab1 */

    memset(kbuf, 0, sizeof(kbuf));
    key_obj_copy(kbuf, sizeof(kbuf), &klen, &ko);
    rc = strncmp(kbuf, "ab1", 3);
    ASSERT_EQ(rc, 0);
}

MTF_DEFINE_UTEST(key_util_test, null_pointers)
{
    struct key_obj ko1, ko2;
    int            rc;

    make_key_obj(&ko1, "abc123", 6, NULL, 0);
    make_key_obj(&ko2, "abc1234", 7, NULL, 0);

    rc = key_obj_ncmp(&ko1, &ko2, 7);
    ASSERT_LT(rc, 0);

    make_key_obj(&ko1, NULL, 0, "abc123", 6);
    make_key_obj(&ko2, NULL, 0, "abc1234", 7);

    rc = key_obj_ncmp(&ko1, &ko2, 7);
    ASSERT_LT(rc, 0);
}

MTF_END_UTEST_COLLECTION(key_util_test)
