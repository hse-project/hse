/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>

#include <hse/hse_limits.h>

#include "../omf.h"
#include "../kblock_reader.h"
#include "../wbt_builder.h"
#include "../wbt_internal.h"
#include "../wbt_reader.h"
#include "../kvs_mblk_desc.h"

#include "mock_mpool.h"

#include <stdlib.h>

/*
 * Reference Tree API
 */
struct _ref_tree {
    struct rb_root root;
    uint   nkeys;

    void  *reft_buf;
    size_t reft_bufsz;
    size_t reft_curr;
} reft;


/* Each node contains one key. */
struct reft_node {
    struct rb_node node;
    void          *key;
    size_t         klen;
};

bool
reft_insert(void *key, size_t klen)
{
    struct rb_node **       link;
    struct rb_node *parent;
    struct rb_root *        root;
    struct reft_node *n;

    root = &reft.root;
    link = &root->rb_node;
    parent = 0;

    while (*link) {
        int rc;

        parent = *link;
        n = container_of(parent, struct reft_node, node);

        rc = keycmp(key, klen, n->key, n->klen);
        if (rc < 0)
            link = &(*link)->rb_left;
        else if (rc > 0)
            link = &(*link)->rb_right;
        else
            return false;
    }

    if (reft.reft_curr + sizeof(*n) + klen > reft.reft_bufsz)
        return false;

    n = reft.reft_buf + reft.reft_curr;
    n->klen = klen;
    n->key = n + 1;
    reft.reft_curr += sizeof(*n);

    memcpy(reft.reft_buf + reft.reft_curr, key, klen);
    reft.reft_curr += klen;

    rb_link_node(&n->node, parent, link);
    rb_insert_color(&n->node, root);

    return true;
}

enum {
    QTYPE_GET,
    QTYPE_SEEK_FWD,
    QTYPE_SEEK_REV,
};

int
reft_lookup(
    void   *in_kdata,
    size_t  in_klen,
    void  **out_kdata,
    size_t *out_klen,
    int     qtype)
{
    struct rb_node *node;
    struct rb_node *last_smaller = rb_first(&reft.root);
    struct rb_node *last_larger = rb_last(&reft.root);
    struct reft_node *n;

    node = reft.root.rb_node;

    while (node) {
        int rc;

        n = container_of(node, struct reft_node, node);

        rc = keycmp(in_kdata, in_klen, n->key, n->klen);
        if (rc < 0) {
            last_larger = node;
            node = node->rb_left;
        } else if (rc > 0) {
            last_smaller = node;
            node = node->rb_right;
        } else {
            last_smaller = last_larger = node;
            break;
        }
    }

    switch (qtype) {
    case QTYPE_GET:
        if (!node)
            goto not_found;

        n = container_of(node, struct reft_node, node);
        break;
    case QTYPE_SEEK_FWD:
        n = container_of(last_larger, struct reft_node, node);
        if (keycmp(n->key, n->klen, in_kdata, in_klen) < 0)
            goto not_found;

        break;
    case QTYPE_SEEK_REV:
        n = container_of(last_smaller, struct reft_node, node);
        if (keycmp(n->key, n->klen, in_kdata, in_klen) > 0)
            goto not_found;

        break;
    }

    *out_kdata = n->key;
    *out_klen  = n->klen;

    return 0;

not_found:
    *out_kdata = NULL;
    *out_klen  = 0;
    return 1;
}

/*
 * WBTree test structs and helper functions.
 */
unsigned char kmd[PAGE_SIZE];
size_t        kmd_used;

struct wbb *wbb;
uint        wbt_pgc;
uint        max_pgc = 1024;

/* Raw list of keys. Use key_iter to iterate through the buffer. */
struct _key_list {
    void  *buf;
    size_t bufsz;
    uint   buf_used;
    uint   nkeys;
} key_list;

struct key_iter {
    size_t        klen;
    unsigned char kdata[];
};

#define BUF_SIZE (128 << 20)

int
pre_collection(struct mtf_test_info *lcl_ti)
{
    mock_mpool_set();

    /* Set up key list */
    key_list.bufsz = BUF_SIZE;
    key_list.buf = malloc(key_list.bufsz);
    ASSERT_NE_RET(NULL, key_list.buf, 0);

    /* Set up rb tree */
    reft.reft_bufsz = BUF_SIZE;
    reft.reft_buf = malloc(reft.reft_bufsz);
    ASSERT_NE_RET(NULL, reft.reft_buf, 0);

    return 0;
}

int
post_collection(struct mtf_test_info *lcl_ti)
{
    free(key_list.buf);
    free(reft.reft_buf);
    mock_mpool_unset();
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(wbt_test, pre_collection, post_collection)

int
pre_test(struct mtf_test_info *lcl_ti)
{
    wbb_create(&wbb, max_pgc, &wbt_pgc);

    kmd_used = 0;
    key_list.buf_used = 0;
    key_list.nkeys = 0;

    reft.reft_curr = 0;
    reft.root = RB_ROOT;
    memset(reft.reft_buf, 0x00, reft.reft_bufsz);

    return 0;
}

int
post_test(struct mtf_test_info *lcl_ti)
{
    wbb_destroy(wbb);
    return 0;
}

void *
wbtree_write(
    struct iovec *iov,
    uint iov_cnt)
{
    int i;
    size_t wlen;
    void *tree, *t;

    for (i = 0, wlen = 0; i < iov_cnt; i++)
        wlen += iov[i].iov_len;

    tree = malloc(wlen);
    if (!tree)
        return 0;

    for(i = 0, t = tree; i < iov_cnt; i++) {
        memcpy(t, iov[i].iov_base, iov[i].iov_len);
        t += iov[i].iov_len;
    }

    return tree;
}

bool
_add_key(struct _key_list *kl, void *key, size_t klen)
{
    struct key_iter *k;

    if (kl->buf_used + sizeof(*k) + klen > kl->bufsz)
        return false;

    k = kl->buf + kl->buf_used;
    k->klen = klen;
    memcpy(k->kdata, key, klen);

    kl->buf_used += sizeof(*k) + klen;
    kl->nkeys++;

    return true;
}

int
_tree_construct(
    struct mtf_test_info *lcl_ti,
    void **tree_out,
    struct wbt_hdr_omf *hdr)
{
    int i;
    struct iovec iov[4096];
    uint iov_cnt;
    merr_t err;
    void *tree; /* serialized nodes and kmd region */
    struct key_iter *k = key_list.buf;

    for (i = 0; i < key_list.nkeys; i++) {
        struct key_obj ko;
        bool added;

        key2kobj(&ko, k->kdata, k->klen);
        kmd_add_zval(kmd, &kmd_used, 1);
        wbb_add_entry(wbb, &ko, 1, kmd, kmd_used, max_pgc, &wbt_pgc, &added);
        ASSERT_TRUE_RET(added, 1);
        kmd_used = 0;
        k = (void *)k + sizeof(*k) + k->klen;
    }

    err = wbb_freeze(wbb, hdr, max_pgc, &wbt_pgc, iov, sizeof(iov), &iov_cnt);
    ASSERT_EQ_RET(0, err, 1);

    tree = wbtree_write(iov, iov_cnt);
    ASSERT_NE_RET(NULL, tree, 1);

    *tree_out = tree;

    return 0;
}

int
_cursor_verify(
    struct mtf_test_info *lcl_ti,
    void *tree,
    struct wbt_hdr_omf *hdr,
    struct _key_list *kl,
    bool reverse)
{
    struct kvs_mblk_desc kbd = {
        .map_base = tree,
    };

    struct wbt_desc wbd = {
        .wbd_first_page = 0,
        .wbd_n_pages = wbt_pgc,
        .wbd_version = WBT_TREE_VERSION, /* The current version */
        .wbd_root = omf_wbt_root(hdr),
        .wbd_leaf = omf_wbt_leaf(hdr),
        .wbd_leaf_cnt = omf_wbt_leaf_cnt(hdr),
        .wbd_kmd_pgc = omf_wbt_kmd_pgc(hdr),
    };

    struct wbti *wbti;
    struct kvs_ktuple kt;
    struct key_obj ko;
    const void *kmd_read;
    bool found;
    int i;
    struct key_iter *k = kl->buf;

    k = kl->buf;
    for (i = 0; i < kl->nkeys; i++) {
        merr_t err;
        uint klen;
        int rc;

        kvs_ktuple_init_nohash(&kt, k->kdata, k->klen);

        err = wbti_create(&wbti, &kbd, &wbd, &kt, reverse, false);
        ASSERT_EQ_RET(0, err, 1);

        /* Get the node prefix only after having called wbti_next(). This is
         * because wbti_next() could have advanced the iterator to the next
         * node which may have a different node pfx/pfx_len.
         */
        found = wbti_next(wbti, &ko.ko_sfx, &ko.ko_sfx_len, &kmd_read);
        if (found)
            wbti_prefix(wbti, &ko.ko_pfx, &ko.ko_pfx_len);
        wbti_destroy(wbti);

        void *fkey;
        size_t fklen;
        int qt = reverse ? QTYPE_SEEK_REV : QTYPE_SEEK_FWD;
        unsigned char kbuf[HSE_KVS_KLEN_MAX];

        reft_lookup(k->kdata, k->klen, &fkey, &fklen, qt);
        key_obj_copy(kbuf, sizeof(kbuf), &klen, &ko);

        /* Compare keys found in the reference rb tree and the wb tree. */
        if (fkey) {
            ASSERT_TRUE_RET(found, 1);
            rc = keycmp(fkey, fklen, kbuf, klen);
            ASSERT_EQ_RET(0, rc, 1);
        } else {
            ASSERT_FALSE_RET(found, 1);
        }

        k = (void *)k + sizeof(*k) + k->klen;
    }

    return 0;
}

int
_get_verify(
    struct mtf_test_info *lcl_ti,
    void *tree,
    struct wbt_hdr_omf *hdr,
    struct _key_list *kl)
{
    struct kvs_mblk_desc kbd = {
        .map_base = tree,
    };

    struct wbt_desc wbd = {
        .wbd_first_page = 0,
        .wbd_n_pages = wbt_pgc,
        .wbd_version = WBT_TREE_VERSION, /* The current version */
        .wbd_root = omf_wbt_root(hdr),
        .wbd_leaf = omf_wbt_leaf(hdr),
        .wbd_leaf_cnt = omf_wbt_leaf_cnt(hdr),
        .wbd_kmd_pgc = omf_wbt_kmd_pgc(hdr),
    };

    struct kvs_ktuple kt;
    struct key_obj ko_ref;
    int i;

    enum key_lookup_res lookup_res;
    struct kvs_vtuple_ref vref;
    struct key_iter *k = kl->buf;

    k = kl->buf;
    for (i = 0; i < kl->nkeys; i++) {
        merr_t err;

        kvs_ktuple_init_nohash(&kt, k->kdata, k->klen);
        key2kobj(&ko_ref, k->kdata, k->klen);

        lookup_res = NOT_FOUND;
        err = wbtr_read_vref(&kbd, &wbd, &kt, 0, 1, &lookup_res, &vref);
        ASSERT_EQ_RET(0, err, 1);

        void  *fkey;
        size_t fklen;

        reft_lookup(k->kdata, k->klen, &fkey, &fklen, QTYPE_GET);
        if (fkey)
            ASSERT_EQ_RET(FOUND_VAL, lookup_res, 1);
        else
            ASSERT_NE_RET(FOUND_VAL, lookup_res, 1);

        k = (void *)k + sizeof(*k) + k->klen;
    }

    return 0;
}

int
_run_test(struct mtf_test_info *lcl_ti, struct _key_list *kl)
{
    /* Step 1: Insert keys and construct the wb tree.
     */
    struct wbt_hdr_omf hdr;
    void *tree;

    _tree_construct(lcl_ti, &tree, &hdr);

    /* Step 2: Verify keys by seeking to and reading each key that was inserted.
     */
    _cursor_verify(lcl_ti, tree, &hdr, kl, false);
    _cursor_verify(lcl_ti, tree, &hdr, kl, true);

    /* Step 3: Verify keys using a point get.
     */
    _get_verify(lcl_ti, tree, &hdr, kl);

    free(tree);

    return 0;
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, basic, pre_test, post_test)
{
    int i, rc;
    char buf[HSE_KVS_KLEN_MAX];
    struct _key_list *ql = &key_list; /* query list */

    memset(buf, 0xfe, sizeof(buf));

    for (i = 0; i < 2000; i++) {
        bool added;

        snprintf(buf, sizeof(buf), "key-%020d", i);
        added = _add_key(&key_list, buf, sizeof(buf));
        ASSERT_TRUE(added);
        added = reft_insert(buf, sizeof(buf));
        ASSERT_TRUE(added);
    }

    rc = _run_test(lcl_ti, ql);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, one_key, pre_test, post_test)
{
    int rc;
    char buf[64];
    bool added;
    struct _key_list *ql = &key_list; /* query list */

    memset(buf, 0xfe, sizeof(buf));
    added = _add_key(&key_list, buf, sizeof(buf));
    ASSERT_TRUE(added);
    added = reft_insert(buf, sizeof(buf));
    ASSERT_TRUE(added);

    rc = _run_test(lcl_ti, ql);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, few_keys, pre_test, post_test)
{
    int i, rc;
    char buf[64];
    size_t nkeys = 100;
    struct _key_list *ql = &key_list; /* query list */

    memset(buf, 0xfe, sizeof(buf));

    for (i = 0; i < nkeys; i++) {
        bool added;

        snprintf(buf, sizeof(buf), "key-%020d", i);
        added = _add_key(&key_list, buf, sizeof(buf));
        ASSERT_TRUE(added);
        added = reft_insert(buf, sizeof(buf));
        ASSERT_TRUE(added);
    }

    rc = _run_test(lcl_ti, ql);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, increasing_length, pre_test, post_test)
{
    int i, rc;
    char buf[HSE_KVS_KLEN_MAX];
    size_t nkeys;
    struct _key_list *ql = &key_list; /* query list */

    memset(buf, 0xfe, sizeof(buf));

    nkeys = HSE_KVS_KLEN_MAX - 30;
    for (i = 0; i < nkeys; i++) {
        bool added;

        snprintf(buf, sizeof(buf), "key-%020d", i);
        added = _add_key(&key_list, buf, i + 30);
        ASSERT_TRUE(added);
        added = reft_insert(buf, i + 30);
        ASSERT_TRUE(added);
    }

    rc = _run_test(lcl_ti, ql);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, large_last_key, pre_test, post_test)
{
    int i, rc;
    char buf[HSE_KVS_KLEN_MAX];
    size_t nkeys = 3000;
    size_t klen = 128;
    const uint lcp = 23;
    const uint lfe_sz = sizeof(struct wbt_lfe_omf);
    const uint hdr_sz = sizeof(struct wbt_node_hdr_omf);
    struct _key_list *ql = &key_list; /* query list */

    /*
     * small_key_space (small_sz) = (klen - lcp + lfe);
     * large_key_space (large_sz) = HSE_KVS_KLEN_MAX - lcp + lfe
     *
     * total_space = (small_sz * nkeys) + large_sz + lcp + wbt_hdr_sz
     *
     * Calculate max value of nkeys such that total_space doesn't exceed
     * PAGE_SIZE.
     */
    uint max_small_keys =
        (PAGE_SIZE - HSE_KVS_KLEN_MAX - lfe_sz - lcp - hdr_sz + lcp) /
        (klen - lcp + lfe_sz);

    memset(buf, 0xfe, sizeof(buf));

    for (i = 1; i <= nkeys; i++) {
        bool added;
        size_t kl = klen;

        /* Changing this key format will affect lcp too. */
        snprintf(buf, sizeof(buf), "key-%020d", i);
        if (i % max_small_keys == 0)
            kl = HSE_KVS_KLEN_MAX;

        added = _add_key(&key_list, buf, kl);
        ASSERT_TRUE(added);
        added = reft_insert(buf, kl);
        ASSERT_TRUE(added);
    }

    rc = _run_test(lcl_ti, ql);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST(wbt_test, varying_large_key)
{
    int i, j, rc;
    char buf[HSE_KVS_KLEN_MAX];
    size_t nkeys = 3000;
    size_t klen = 64;
    struct _key_list *ql = &key_list; /* query list */

    memset(buf, 0xfe, sizeof(buf));

    for (i = 3; i < 100; i++) {
        pre_test(lcl_ti);
        for (j = 1; j < nkeys; j++) {
            bool added;
            size_t kl = klen;

            snprintf(buf, sizeof(buf), "key-%020d", j);
            if (j % i == 0)
                kl = HSE_KVS_KLEN_MAX;

            added = _add_key(&key_list, buf, kl);
            ASSERT_TRUE(added);
            added = reft_insert(buf, kl);
            ASSERT_TRUE(added);
        }

        rc = _run_test(lcl_ti, ql);
        ASSERT_EQ(0, rc);
        post_test(lcl_ti);
    }
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, small_last_key, pre_test, post_test)
{
    int i, rc;
    char buf[HSE_KVS_KLEN_MAX];
    size_t nkeys = 3000;
    size_t large_klen = HSE_KVS_KLEN_MAX;
    const int keys_per_node = 4;
    struct _key_list *ql = &key_list; /* query list */

    memset(buf, 0xfe, sizeof(buf));

    for (i = 1; i <= nkeys; i++) {
        bool added;
        size_t klen = large_klen;

        snprintf(buf, sizeof(buf), "key-%08d", i);
        if (i % keys_per_node == 0)
            klen = 64;

        added = _add_key(&key_list, buf, klen);
        ASSERT_TRUE(added);
        added = reft_insert(buf, klen);
        ASSERT_TRUE(added);
    }

    rc = _run_test(lcl_ti, ql);
    ASSERT_EQ(0, rc);
}

MTF_DEFINE_UTEST_PREPOST(wbt_test, skip_keys, pre_test, post_test)
{
    int i, rc;
    char buf[HSE_KVS_KLEN_MAX];
    size_t nkeys = 100 * 1000;
    size_t klen = 64;
    struct _key_list ql = {0}; /* query list */

    memset(buf, 0xfe, sizeof(buf));
    ql.bufsz = 2 * BUF_SIZE;
    ql.buf = malloc(ql.bufsz);
    ASSERT_NE(NULL, ql.buf);

    for (i = 0; i < 2 * nkeys; i++) {
        bool added;

        snprintf(buf, sizeof(buf), "key-%032d", i);

        /* Add only even numbered keys to the wbtree */
        if (i % 2 == 0) {
            added = _add_key(&key_list, buf, klen);
            ASSERT_TRUE(added);
            added = reft_insert(buf, klen);
            ASSERT_TRUE(added);
        }

        /* Add all keys to query list */
        added = _add_key(&ql, buf, klen);
        ASSERT_TRUE(added);
    }

    rc = _run_test(lcl_ti, &ql);
    ASSERT_EQ(0, rc);

    free(ql.buf);
}

MTF_END_UTEST_COLLECTION(wbt_test)
