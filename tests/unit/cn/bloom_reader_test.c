/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <hse/test/mtf/framework.h>

#include <hse/ikvdb/tuple.h>

#include <hse/logging/logging.h>
#include <hse/util/page.h>
#include <hse/util/bloom_filter.h>

#include "cn/omf.h"
#include "cn/bloom_reader.h"
#include "cn/wbt_internal.h"

#include <hse/test/mock/mock_mpool.h>

char data_path[PATH_MAX / 2];

char *kblock_files[] = {
#if HSE_OMF_BYTE_ORDER == __ORDER_BIG_ENDIAN__
    "simple_1031c.kb5_w6_b5-be.xz",
    "simple_1c.kb5_w6_b5-be.xz"
#else
    "simple_1031c.kb5_w6_b5.xz",
    "simple_1c.kb5_w6_b5.xz"
#endif
};

int
test_collection_setup(struct mtf_test_info *info)
{
    struct mtf_test_coll_info *coll_info = info->ti_coll;
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
    struct bloom_desc     rgndesc = { 0 };
    struct kblock_hdr_omf kb_hdr;
    struct bloom_hdr_omf  blm_hdr;
    struct kvs_ktuple     ktuple;
    bool                  hit;
    uint                  i, cnt, fpc;
    char *                endptr;
    char                  filename[PATH_MAX];
    char                  keybuf[32];
    struct kvs_mblk_desc  blkdesc = { 0 };
    uint64_t              blkid;
    uint8_t *             blm_pages;

    snprintf(filename, sizeof(filename), "%s/%s", data_path, kblock_file);

    log_debug("Testing with kblock %s", filename);

    err = mpm_mblock_alloc_file(&blkid, filename);
    ASSERT_EQ(0, err);
    blkdesc.mbid = blkid;

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

    rgndesc.bd_bitmap = blm_pages;

    for (i = fpc = 0; i < cnt; ++i) {
        int len;

        /* Format key to match what simple_client tool uses */
        len = snprintf(keybuf, sizeof(keybuf), "k%u", i);

        kvs_ktuple_init(&ktuple, keybuf, len);

        hit = bloom_reader_lookup(&rgndesc, ktuple.kt_hash);
        ASSERT_TRUE(hit);

        /* Permute the hash to try and elicit a false positive.
         */
        hit = bloom_reader_lookup(&rgndesc, ~(ktuple.kt_hash));
        if (hit)
            ++fpc;
    }

    /* Something's horriby wrong if the false positive rate high.
     */
    ASSERT_LT((fpc * 1000) / cnt, 25); /* < 2.5% */

    free(blm_pages);
}

MTF_DEFINE_UTEST_PRE(bloom_reader_test, basic_blm_test, test_prehook)
{
    int i;

    for (i = 0; i < NELEM(kblock_files); i++)
        read_blooms(lcl_ti, kblock_files[i]);
}

MTF_END_UTEST_COLLECTION(bloom_reader_test)
