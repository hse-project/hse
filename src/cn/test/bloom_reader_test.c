/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/bloom_filter.h>

#include "../omf.h"
#include "../bloom_reader.h"
#include "../wbt_internal.h"

#include "mock_mpool.h"

char data_path[PATH_MAX / 2];

char *kblock_files[] = { "simple_1031c.kb3_w3_b4.xz", "simple_1c.kb3_w3_b4.xz" };

int
test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *coll_info = info->ti_coll;
    int                        len;

    hse_openlog("bloom_reader_test", 1);

    if (coll_info->tci_argc != 2) {
        hse_log(HSE_ERR "Usage:  %s <mblock_image_dir>", coll_info->tci_argv[0]);
        return -1;
    }

    len = strlen(coll_info->tci_argv[1]);
    if (coll_info->tci_argv[1][len - 1] == '/')
        coll_info->tci_argv[1][len - 1] = 0;
    strncpy(data_path, coll_info->tci_argv[1], sizeof(data_path) - 1);

    return 0;
}

int
test_collection_teardown(struct mtf_test_info *info)
{
    mock_mpool_unset();
    return 0;
}

int
test_prehook(struct mtf_test_info *info)
{
    mock_mpool_set();
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    bloom_reader_test,
    test_collection_setup,
    test_collection_teardown);

void
read_blooms(struct mtf_test_info *lcl_ti, char *kblock_file)
{
    merr_t                err;
    struct mpool *        ds = (void *)-1;
    struct bloom_desc     rgndesc = {};
    struct kblock_hdr_omf kb_hdr;
    struct bloom_hdr_omf  blm_hdr;
    struct kvs_ktuple     ktuple;
    bool                  hit;
    uint                  i, cnt, fpc;
    char *                endptr;
    char                  filename[PATH_MAX];
    char                  keybuf[100];
    struct kvs_mblk_desc  blkdesc;
    u64                   blkid;
    u8 *                  blm_pages;

    snprintf(filename, sizeof(filename), "%s/%s", data_path, kblock_file);

    hse_log(HSE_DEBUG "Testing with kblock %s", filename);

    err = mpm_mblock_alloc_file(&blkid, filename);
    ASSERT_EQ(0, err);
    blkdesc.mb_id = blkid;
    blkdesc.map_idx = 0;

    err = mpool_mcache_mmap(ds, 1, &blkdesc.mb_id, MPC_VMA_COLD, &blkdesc.map);
    ASSERT_EQ(0, err);

    mpm_mblock_read(blkid, &kb_hdr, 0, sizeof(struct kblock_hdr_omf));
    ASSERT_EQ(sizeof(struct bloom_hdr_omf), omf_kbh_blm_hlen(&kb_hdr));

    mpm_mblock_read(blkid, &blm_hdr, omf_kbh_blm_hoff(&kb_hdr), omf_kbh_blm_hlen(&kb_hdr));

    ASSERT_EQ(omf_bh_magic(&blm_hdr), BLOOM_OMF_MAGIC);
    ASSERT_EQ(omf_bh_version(&blm_hdr), BLOOM_OMF_VERSION);

    ASSERT_GE(omf_bh_bktshift(&blm_hdr), 9);
    ASSERT_LE(omf_bh_bktshift(&blm_hdr), 16);

    ASSERT_GT(omf_bh_rotl(&blm_hdr), 0);
    ASSERT_LT(omf_bh_rotl(&blm_hdr), 64);
    ASSERT_TRUE(omf_bh_rotl(&blm_hdr) & 1);

    /* mimic kblock_reader.read_blm_region_desc() */
    rgndesc.bd_first_page = omf_kbh_blm_doff_pg(&kb_hdr);
    rgndesc.bd_n_pages = omf_kbh_blm_dlen_pg(&kb_hdr);

    rgndesc.bd_modulus = omf_bh_modulus(&blm_hdr);
    rgndesc.bd_bktshift = omf_bh_bktshift(&blm_hdr);
    rgndesc.bd_bktmask = (1u << rgndesc.bd_bktshift) - 1;
    rgndesc.bd_rotl = omf_bh_rotl(&blm_hdr);
    rgndesc.bd_n_hashes = omf_bh_n_hashes(&blm_hdr);

    blm_pages = mapi_safe_malloc(omf_bh_bitmapsz(&blm_hdr));
    ASSERT_TRUE(blm_pages != NULL);

    mpm_mblock_read(blkid, blm_pages, rgndesc.bd_first_page * PAGE_SIZE, omf_bh_bitmapsz(&blm_hdr));

    /* The first number in the name should be the key count.
     */
    while (*kblock_file && !isdigit(*kblock_file))
        ++kblock_file;
    cnt = strtoul(kblock_file, &endptr, 0);
    ASSERT_NE(kblock_file, endptr);
    ASSERT_GT(cnt, 0);

    for (i = fpc = 0; i < cnt; ++i) {
        ktuple.kt_data = keybuf;
        ktuple.kt_hash = 0;

        /* Format key to match what simple_client tool uses */
        ktuple.kt_len = snprintf(keybuf, sizeof(keybuf), "k%u", i);

        hit = bloom_reader_buffer_lookup(&rgndesc, blm_pages, &ktuple);
        ASSERT_TRUE(hit);

        hit = false;
        err = bloom_reader_mcache_lookup(&rgndesc, &blkdesc, &ktuple, &hit);
        ASSERT_EQ(0, err);
        ASSERT_TRUE(hit);

        /* Permute the hash to try and elicit a false positive.
         */
        ktuple.kt_hash = ~ktuple.kt_hash;
        hit = bloom_reader_buffer_lookup(&rgndesc, blm_pages, &ktuple);
        if (hit)
            ++fpc;
    }

    /* Something's horriby wrong if the false positive rate high.
     */
    ASSERT_LT((fpc * 1000) / cnt, 25); /* < 2.5% */

    err = mpool_mcache_munmap(blkdesc.map);
    ASSERT_EQ(0, err);

    free(blm_pages);
}

MTF_DEFINE_UTEST_PRE(bloom_reader_test, basic_blm_test, test_prehook)
{
    int i;

    for (i = 0; i < NELEM(kblock_files); i++)
        read_blooms(lcl_ti, kblock_files[i]);
}

MTF_DEFINE_UTEST_PRE(bloom_reader_test, t_bloom_reader_filter_info, test_prehook)
{
    merr_t            err;
    struct bloom_desc desc;
    u32               modulus;
    u32               hashes;

    modulus = 0;
    hashes = 0;
    desc.bd_modulus = 1234;
    desc.bd_n_hashes = 7;
    err = bloom_reader_filter_info(&desc, &hashes, &modulus);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(hashes, 7);
    ASSERT_EQ(modulus, 1234);
}

MTF_END_UTEST_COLLECTION(bloom_reader_test)
