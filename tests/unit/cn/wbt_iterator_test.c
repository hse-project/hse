/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/logging.h>
#include <hse_util/keycmp.h>

#include <hse/limits.h>

#include <cn/omf.h>
#include <cn/kblock_reader.h>
#include <cn/wbt_internal.h>
#include <cn/wbt_reader.h>
#include <cn/kvs_mblk_desc.h>

#include <mocks/mock_mpool.h>

char data_path[PATH_MAX / 2];

struct test_kblock {
    uint  n_keys;
    bool  null_terminated;
    uint  key_modifier;
    char *key_fmt;
    char *file;
};

/* clang-format off */

struct test_kblock kblocks[] = {
#if HSE_OMF_BYTE_ORDER == __ORDER_BIG_ENDIAN__
    { 1031, false,    0,      "k%u", "simple_1031c.kb5_w6_b5-be.xz" },
    {  500, false,    0, "key.%09d", "simple_500c.kb5_w6_b5-be.xz" },
    {    1, false,    0,      "k%u", "simple_1c.kb5_w6_b5-be.xz" },
    {   10, false, 1024,      "k%x", "multival_10keys_2000vals.kb5_w6_b5-be.xz" },
#else
    { 1031, false,    0,      "k%u", "simple_1031c.kb5_w6_b5.xz" },
    {  500, false,    0, "key.%09d", "simple_500c.kb5_w6_b5.xz" },
    {    1, false,    0,      "k%u", "simple_1c.kb5_w6_b5.xz" },
    {  100, false, 1024,      "k%x", "multival_100keys_4vals.kb5_w6_b5.xz" },
    {   10, false, 1024,      "k%x", "multival_10keys_2000vals.kb5_w6_b5.xz" },
#endif
};

/* clang-format on */

int
keyv_cmp(const void *lhs, const void *rhs)
{
    const char *const *l = lhs;
    const char *const *r = rhs;

    return keycmp(*l, strlen(*l), *r, strlen(*r));
}

char **
keyv_create(struct test_kblock *kblock)
{
    char   keybuf[128];
    char **keyv;
    uint   i;

    keyv = calloc(kblock->n_keys, sizeof(*keyv));
    assert(keyv);

    for (i = 0; i < kblock->n_keys; ++i) {
        int n;

        n = snprintf(keybuf, sizeof(keybuf), kblock->key_fmt, kblock->key_modifier + i);
        if (n < 1 || n > sizeof(keybuf))
            abort();

        keyv[i] = strdup(keybuf);
        assert(keyv[i]);
    }

    /* Sort the keys in the order we expect them to be
     * returned by the wbt iterator.
     */
    qsort(keyv, kblock->n_keys, sizeof(*keyv), keyv_cmp);

    return keyv;
}

void
keyv_destroy(struct test_kblock *kblock, char **keyv)
{
    uint i;

    for (i = 0; i < kblock->n_keys; ++i)
        free(keyv[i]);
    free(keyv);
}

int
setup(struct mtf_test_info *lcl_ti)
{
    struct mtf_test_coll_info *coll_info = lcl_ti->ti_coll;
    int                        len, idx;

    if (coll_info->tci_argc - coll_info->tci_optind != 1) {
        log_err("Usage: %s [test framework options] <mblock_image_dir>", coll_info->tci_argv[0]);
        return -1;
    }

    idx = coll_info->tci_optind;

    len = strlen(coll_info->tci_argv[idx]);
    if (coll_info->tci_argv[idx][len - 1] == '/')
        coll_info->tci_argv[idx][len - 1] = 0;
    strncpy(data_path, coll_info->tci_argv[idx], sizeof(data_path) - 1);

    return 0;
}

int
teardown(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
pre(struct mtf_test_info *lcl_ti)
{
    struct mtf_test_coll_info *coll_info = lcl_ti->ti_coll;
    merr_t                     err;

    err = wbti_init();
    if (err) {
        log_errx("%s: wbti_init failed: @@e", err, coll_info->tci_argv[0]);
        return -1;
    }

    mock_mpool_set();

    return 0;
}

int
post(struct mtf_test_info *lcl_ti)
{
    mock_mpool_unset();
    wbti_fini();

    return 0;
}

int
load_kblock(
    struct mtf_test_info *lcl_ti,
    const char *          kblock_file,
    struct kvs_mblk_desc *kblk_desc,
    struct wbt_desc *     desc)
{
    merr_t err;
    u64    blkid;
    char   filename[PATH_MAX];
    void * wbt_hdr;

    memset(desc, 0, sizeof(*desc));
    memset(kblk_desc, 0, sizeof(*kblk_desc));

    snprintf(filename, sizeof(filename), "%s/%s", data_path, kblock_file);

    log_debug("Testing with kblock %s", filename);

    err = mpm_mblock_alloc_file(&blkid, filename);
    ASSERT_EQ_RET(err, 0, -1);

    /* create mmap for mblock */
    kblk_desc->mbid = blkid;
    kblk_desc->map_idx = 0;
    kblk_desc->map_base = 0;
    kblk_desc->ds = (struct mpool *)-1;

    err = mpool_mcache_mmap(kblk_desc->ds, 1, &blkid, &kblk_desc->map);
    ASSERT_EQ_RET(err, 0, -1);

    kblk_desc->map_base = mpool_mcache_getbase(kblk_desc->map, kblk_desc->map_idx);
    ASSERT_NE_RET(kblk_desc->map_base, NULL, -1);

    wbt_hdr = kblk_desc->map_base + omf_kbh_wbt_hoff(kblk_desc->map_base);
    desc->wbd_first_page = omf_kbh_wbt_doff_pg(kblk_desc->map_base);
    desc->wbd_n_pages = omf_kbh_wbt_dlen_pg(kblk_desc->map_base);

    err = wbtr_read_desc(wbt_hdr, desc);
    ASSERT_EQ_RET(err, 0, -1);

    mpool_mcache_munmap(kblk_desc->map);

    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(wbti_test, setup, teardown);

MTF_DEFINE_UTEST_PREPOST(wbti_test, t_wbti_create_fail_nomem, pre, post)
{
    merr_t               err;
    struct wbti *        wbti;
    struct kvs_mblk_desc kbd;
    struct wbt_desc      desc;
    u32                  cache_spill_wbt = 1;

    if (load_kblock(lcl_ti, kblocks[0].file, &kbd, &desc))
        return;

    /* allocation failure */
    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    err = wbti_create(&wbti, kbd.map_base, &desc, 0, false, cache_spill_wbt);
    ASSERT_EQ(ENOMEM, merr_errno(err));
}

MTF_DEFINE_UTEST_PREPOST(wbti_test, t_wbti_destroy, pre, post)
{
    wbti_destroy(0);
}

void
t_iterate_helper(struct mtf_test_info *lcl_ti, struct test_kblock *kblock)
{
    merr_t               err;
    struct wbti *        wbti;
    struct kvs_mblk_desc kbd = {};
    struct wbt_desc      desc = {};
    int                  cnt, inc;
    bool                 eof;
    u32                  cache_spill_wbt = 1;
    const void *         kdata;
    const void *         kmd;
    uint                 klen, xlen;
    unsigned char        seekbuf[HSE_KVS_KEY_LEN_MAX];
    struct kvs_ktuple    seek = { 0, 0 };
    char **              keyv;

    if (load_kblock(lcl_ti, kblock->file, &kbd, &desc))
        return;

    keyv = keyv_create(kblock);

    cnt = 0;
    inc = 1;

reverse:
    err = wbti_create(&wbti, kbd.map_base, &desc, 0, inc < 0, cache_spill_wbt);
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(wbti);

    if (inc < 0) {
        memset(seekbuf, 0xff, sizeof(seekbuf));
        seek.kt_data = seekbuf;
        seek.kt_len = sizeof(seekbuf);
    }

    wbti_destroy(wbti);
    wbti = 0;

    err = wbti_create(&wbti, kbd.map_base, &desc, &seek, (inc < 1), cache_spill_wbt);
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(wbti);

    while (1) {
        const void *pfx;
        uint        plen = 0;
        int         rc;

        if (!wbti_next(wbti, &kdata, &klen, &kmd))
            break;

        ASSERT_GE(cnt, 0);
        ASSERT_LT(cnt, kblock->n_keys);

        wbti_prefix(wbti, &pfx, &plen);
        xlen = strlen(keyv[cnt]) - plen + (kblock->null_terminated ? 1 : 0);
        ASSERT_EQ(klen, xlen);

		if (pfx) {
			rc = memcmp(pfx, keyv[cnt], plen);
			ASSERT_EQ(0, rc);
		}
        rc = memcmp(kdata, keyv[cnt] + plen, klen);
        ASSERT_EQ(0, rc);

        cnt += inc;
    }
    if (inc > 0)
        ASSERT_EQ(kblock->n_keys, cnt);
    else
        ASSERT_EQ(-1, cnt);

    /* calling next again should return eof again w/o errors */
    eof = wbti_next(wbti, &kdata, &klen, &kmd);
    ASSERT_FALSE(eof);

    wbti_destroy(wbti);

    if (inc > 0) {
        cnt = kblock->n_keys - 1; /* start at end and iter backwards */
        inc = -1;
        goto reverse;
    }

    keyv_destroy(kblock, keyv);
}

void
t_seek_helper(struct mtf_test_info *lcl_ti, struct test_kblock *kblock, bool reverse, bool full)
{
    merr_t               err;
    struct wbti *        wbti;
    struct kvs_mblk_desc kbd;
    struct wbt_desc      desc;
    struct kvs_ktuple    seek;
    int                  exp, inc, idx, cnt;
    bool                 eof;
    u32                  cache_leaves = 1;
    const void *         kdata;
    const void *         kmd;
    uint                 klen, xlen;
    char **              keyv;
    const void *         pfx;
    uint                 plen;

    if (load_kblock(lcl_ti, kblock->file, &kbd, &desc))
        return;

    keyv = keyv_create(kblock);

    inc = reverse ? -1 : 1;

    if (full) {
        /* attempt to seek cursor to a key outside the range */
        idx = reverse ? kblock->n_keys - 1 : 0;
        xlen = strlen(keyv[idx]) + (kblock->null_terminated ? 1 : 0);
        seek.kt_data = reverse ? "l" : "j";
        seek.kt_len = 1;
    } else {
        /* attempt to seek cursor to mid point of the range */
        idx = kblock->n_keys / 2;
        xlen = strlen(keyv[idx]) + (kblock->null_terminated ? 1 : 0);
        seek.kt_data = keyv[idx];
        seek.kt_len = xlen;
    }

    err = wbti_create(&wbti, kbd.map_base, &desc, &seek, reverse, cache_leaves);
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(wbti);

    cnt = 0;
    while (1) {
        int rc;

        if (!wbti_next(wbti, &kdata, &klen, &kmd))
            break;

        wbti_prefix(wbti, &pfx, &plen);
        xlen = strlen(keyv[idx]) - plen + (kblock->null_terminated ? 1 : 0);
        ASSERT_EQ(klen, xlen);

		if (pfx) {
        	rc = memcmp(pfx, keyv[idx], plen);
        	ASSERT_EQ(0, rc);
		}
        rc = memcmp(kdata, keyv[idx] + plen, klen);
        ASSERT_EQ(0, rc);
        idx += inc;
        ++cnt;
    }

    exp = reverse ? -1 : kblock->n_keys;
    ASSERT_EQ(exp, idx);

    if (full)
        exp = kblock->n_keys;
    else if (reverse)
        exp = (kblock->n_keys / 2) + 1;
    else
        exp = kblock->n_keys - (kblock->n_keys / 2);

    ASSERT_EQ(exp, cnt);

    /* calling next again should return eof again w/o errors */
    eof = wbti_next(wbti, &kdata, &klen, &kmd);
    ASSERT_FALSE(eof);

    wbti_destroy(wbti);
    keyv_destroy(kblock, keyv);
}

MTF_DEFINE_UTEST_PREPOST(wbti_test, t_iter_seek, pre, post)
{
    int i;

    for (i = 0; i < NELEM(kblocks); i++) {
        t_seek_helper(lcl_ti, &kblocks[i], false, false);
        t_seek_helper(lcl_ti, &kblocks[i], false, true);
        t_seek_helper(lcl_ti, &kblocks[i], true, false);
        t_seek_helper(lcl_ti, &kblocks[i], true, true);
    }
}

MTF_DEFINE_UTEST_PREPOST(wbti_test, t_iterate, pre, post)
{
    int i;

    for (i = 0; i < NELEM(kblocks); i++)
        t_iterate_helper(lcl_ti, &kblocks[i]);
}

MTF_END_UTEST_COLLECTION(wbti_test)
