/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/base.h>
#include <hse_util/keycmp.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/omf_kmd.h>

#include <cn/cn_tree_cursor.h>
#include <cn/cn_tree_internal.h>
#include <cn/cn_cursor.h>
#include <cn/kvset.h>
#include <cn/route.h>

struct cn_kv_item;

struct cn_tree tree;
struct kv_iterator dummy_kviter;

void *
_cn_get_tree(const struct cn *cn)
{
    return &tree;
}

merr_t
cn_tree_kvset_refs(struct cn_tree_node *node, struct cn_level_cursor *lcur)
{
    return 0;
}

struct kv {
    struct cn_kv_item item;
    char              kdata[32];
    uint              klen;
    enum kmd_vtype    vtype;
    u64               seqno;
    struct kv        *next;
    struct kv        *prev;
} *head, *curr;

void
kv_start()
{
    head = curr = NULL;
}

void
kv_add(struct kv *kv, const char *keystr, u64 seqno, enum kmd_vtype vtype)
{
    snprintf(kv->kdata, sizeof(kv->kdata), "%s", keystr);
    kv->klen = strlen(keystr);
    kv->vtype = vtype;
    kv->seqno = seqno;
    kv->next = NULL;

    if (!curr) {
        head = curr = kv;
        kv->prev = NULL;
        return;
    }

    curr->next = kv;
    kv->prev = curr;
    curr = kv;
}

void
kv_end()
{
    curr = head;
}

bool
_bin_heap2_pop(struct bin_heap2 *bh, void **item)
{
    if (!curr)
        return false; /* eof */

    key2kobj(&curr->item.kobj, curr->kdata, curr->klen);
    curr->item.vctx.kmd = curr;
    curr->item.vctx.next = 0;
    curr->item.vctx.nvals = 1;
    curr->item.src = &dummy_kviter.kvi_es;

    *item = &curr->item;
    curr = curr->next;

    return true;
}

bool
_bin_heap2_peek(struct bin_heap2 *bh, void **item)
{
    if (!curr)
        return false; /* eof */

    memset(&curr->item, 0x00, sizeof(curr->item));
    key2kobj(&curr->item.kobj, curr->kdata, curr->klen);
    curr->item.vctx.kmd = curr;
    curr->item.vctx.next = 0;
    curr->item.vctx.nvals = 1;
    curr->item.src = &dummy_kviter.kvi_es;
    curr->item.vctx.is_ptomb = (curr->vtype == vtype_ptomb);

    *item = &curr->item;
    return true;
}

bool
_kvset_iter_next_vref(
    struct kv_iterator *    handle,
    struct kvset_iter_vctx *vc,
    u64 *                   seq,
    enum kmd_vtype *        vtype,
    uint *                  vbidx,
    uint *                  vboff,
    const void **           vdata,
    uint *                  vlen,
    uint *                  complen)
{
    struct kv *kv = (void *)vc->kmd;

    if (vc->next >= vc->nvals)
        return false;

    *seq = kv->seqno;
    *vtype = kv->vtype;

    ++vc->next;

    return true;
}

merr_t
_kvset_iter_val_get(
    struct kv_iterator *    handle,
    struct kvset_iter_vctx *vc,
    enum kmd_vtype          vtype,
    uint                    vbidx,
    uint                    vboff,
    const void **           vdata,
    uint *                  vlen,
    uint *                  complen)
{
    struct kv *kv = (void *)vc->kmd;

    switch (vtype) {
    case vtype_ival:
    case vtype_val:
    case vtype_cval:
        *vdata = kv->kdata;
        *vlen = kv->klen;
        break;
    case vtype_tomb:
        *vlen = 0;
        *vdata = HSE_CORE_TOMB_REG;
        break;
    case vtype_ptomb:
        *vlen = 0;
        *vdata = HSE_CORE_TOMB_PFX;
        break;
    case vtype_zval:
        *vdata = 0;
        *vlen = 0;
        break;
    }

    return 0;
}

/* This is a mock */
merr_t
cn_lcur_init(
    struct cn_level_cursor *lcur)
{
    /* Set number of iterators to some non-zero value so the code doesn't skip seek.
     */
    lcur->cnlc_iterc = 1;
    return 0;
}

/* This is a mock */
merr_t
cn_lcur_seek(
    struct cn_level_cursor *lcur,
    const void             *key,
    u32                     len)
{
    curr = head;
    while (curr) {
        int rc = keycmp(curr->kdata, curr->klen, key, len);

        if (rc >= 0)
            return 0;

        curr = curr->next;
    }

    return 0;
}

int
pre_test(struct mtf_test_info *lcl_ti)
{
    mapi_inject(mapi_idx_rmlock_rlock, 0);
    mapi_inject(mapi_idx_rmlock_runlock, 0);

    mapi_inject(mapi_idx_kvset_get_ref, 0);
    mapi_inject(mapi_idx_kvset_put_ref, 0);
    mapi_inject(mapi_idx_kvset_get_dgen, 0);

    mapi_inject(mapi_idx_cn_get_maint_wq, 0);

    MOCK_SET(cn, _cn_get_tree);

    mapi_inject(mapi_idx_kvset_iter_create, 0);
    mapi_inject(mapi_idx_kvset_iter_release, 0);
    mapi_inject(mapi_idx_kvset_iter_seek, 0);
    mapi_inject(mapi_idx_kvset_iter_es_get, 0);
    mapi_inject(mapi_idx_kvset_iter_kvset_get, 0);

    MOCK_SET(kvset, _kvset_iter_next_vref);
    MOCK_SET(kvset, _kvset_iter_val_get);

    mapi_inject(mapi_idx_bin_heap2_create, 0);
    mapi_inject(mapi_idx_bin_heap2_destroy, 0);
    mapi_inject(mapi_idx_bin_heap2_prepare, 0);

    MOCK_SET(bin_heap, _bin_heap2_peek);
    MOCK_SET(bin_heap, _bin_heap2_pop);

    return 0;
}

int
post_test(struct mtf_test_info *lcl_ti)
{
    mapi_inject_clear();
    MOCK_UNSET(cn, _cn_get_tree);
    return 0;
}

int
cmp(const char *expstr, struct kvs_cursor_element *elem)
{
    struct key_obj ko;

    key2kobj(&ko, expstr, strlen(expstr));
    return key_obj_cmp(&elem->kce_kobj, &ko);
}

MTF_BEGIN_UTEST_COLLECTION(cn_tree_cursor_test)

MTF_DEFINE_UTEST_PREPOST(cn_tree_cursor_test, empty, pre_test, post_test)
{
    merr_t err;
    struct cn_cursor cur = {};
    struct kvs_cparams cp = kvs_cparams_defaults();
    struct cn_tree_node tn;
    struct route_node *rnode;
    const char ekey = 'z';

    tree.ct_route_map = route_map_create(&cp, "KVS-non-existent-routemap");
    rnode = route_map_insert(tree.ct_route_map, &tn, &ekey, sizeof(ekey), 0);
    ASSERT_NE(NULL, rnode);

    err = cn_tree_cursor_create(&cur);
    ASSERT_EQ(0, err);

    const char *key = "key01";

    err = cn_tree_cursor_seek(&cur, key, strlen(key), NULL);
    ASSERT_EQ(0, err);

    struct kvs_cursor_element elem;
    bool eof = false;

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    cn_tree_cursor_destroy(&cur);

    route_map_delete(tree.ct_route_map, rnode);

    route_map_destroy(tree.ct_route_map);
}

MTF_DEFINE_UTEST_PREPOST(cn_tree_cursor_test, basic, pre_test, post_test)
{
    merr_t err;
    struct cn_cursor cur = {
        .cncur_seqno = 10,
    };
    struct kvs_cparams cp = kvs_cparams_defaults();
    struct cn_tree_node tn;
    struct route_node *rnode;
    const char ekey = 'z';

    struct kv kv[2];

    tree.ct_route_map = route_map_create(&cp, "KVS-non-existent-routemap");
    rnode = route_map_insert(tree.ct_route_map, &tn, &ekey, sizeof(ekey), 0);
    ASSERT_NE(NULL, rnode);

    kv_start();
    kv_add(&kv[0], "key01", 1, vtype_val);
    kv_add(&kv[1], "key02", 1, vtype_val);
    kv_end();

    err = cn_tree_cursor_create(&cur);
    ASSERT_EQ(0, err);

    struct kvs_cursor_element elem;
    bool eof = false;

    const char *seek = "key";
    err = cn_tree_cursor_seek(&cur, seek, strlen(seek), NULL);
    ASSERT_EQ(0, err);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp(kv[0].kdata, &elem));
    ASSERT_EQ(0, keycmp(elem.kce_vt.vt_data, elem.kce_vt.vt_xlen, kv[0].kdata, kv[0].klen));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp(kv[1].kdata, &elem));
    ASSERT_EQ(0, keycmp(elem.kce_vt.vt_data, elem.kce_vt.vt_xlen, kv[1].kdata, kv[1].klen));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    seek = "key02";
    err = cn_tree_cursor_seek(&cur, seek, strlen(seek), NULL);
    ASSERT_EQ(0, err);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp(kv[1].kdata, &elem));
    ASSERT_EQ(0, keycmp(elem.kce_vt.vt_data, elem.kce_vt.vt_xlen, kv[1].kdata, kv[1].klen));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    cn_tree_cursor_destroy(&cur);

    route_map_delete(tree.ct_route_map, rnode);
    route_map_destroy(tree.ct_route_map);
}

MTF_DEFINE_UTEST_PREPOST(cn_tree_cursor_test, dups, pre_test, post_test)
{
    merr_t err;
    struct cn_cursor cur = {
        .cncur_seqno = 10,
    };
    struct kvs_cparams cp = kvs_cparams_defaults();
    struct cn_tree_node tn;
    struct route_node *rnode;
    const char ekey = 'z';

    struct kv kv[4];

    kv_start();
    kv_add(&kv[0], "key01", 2, vtype_val);
    kv_add(&kv[1], "key01", 1, vtype_val);
    kv_add(&kv[2], "key02", 2, vtype_tomb);
    kv_add(&kv[3], "key02", 1, vtype_val);
    kv_end();

    tree.ct_route_map = route_map_create(&cp, "KVS-non-existent-routemap");
    rnode = route_map_insert(tree.ct_route_map, &tn, &ekey, sizeof(ekey), 0);
    ASSERT_NE(NULL, rnode);

    err = cn_tree_cursor_create(&cur);
    ASSERT_EQ(0, err);

    struct kvs_cursor_element elem;
    bool eof = false;

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp(kv[0].kdata, &elem));
    ASSERT_EQ(0, keycmp(elem.kce_vt.vt_data, elem.kce_vt.vt_xlen, kv[0].kdata, kv[0].klen));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp(kv[2].kdata, &elem));
    ASSERT_TRUE(HSE_CORE_IS_TOMB(elem.kce_vt.vt_data));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    const char *seek = "key02";
    err = cn_tree_cursor_seek(&cur, seek, strlen(seek), NULL);
    ASSERT_EQ(0, err);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp(kv[2].kdata, &elem));
    ASSERT_TRUE(HSE_CORE_IS_TOMB(elem.kce_vt.vt_data));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    cn_tree_cursor_destroy(&cur);

    route_map_delete(tree.ct_route_map, rnode);
    route_map_destroy(tree.ct_route_map);
}

MTF_DEFINE_UTEST_PREPOST(cn_tree_cursor_test, with_ptomb, pre_test, post_test)
{
    merr_t err;
    const char *pfxstr = "a";
    struct cn_cursor cur = {
        .cncur_seqno = 10,
        .cncur_tree_pfxlen = 2,
        .cncur_pfx = pfxstr,
        .cncur_pfxlen = strlen(pfxstr),
    };
    struct kvs_cparams cp = kvs_cparams_defaults();
    struct cn_tree_node tn;
    struct route_node *rnode;
    const char ekey = 'z';

    /* memory for the kv tuples */
    struct kv kv[10];

    /* Ptombs are not passed up the stack, but they will affect future keys.
     */

    kv_start();
    kv_add(&kv[0], "ab",   4,  vtype_val);    /* Seen */
    kv_add(&kv[1], "ab",   4,  vtype_ptomb);  /* Hidden: Not passed up the stack, only affects future keys */
    kv_add(&kv[2], "ab",   1,  vtype_ptomb);  /* Hidden: dup pt, first pt takes precendence */
    kv_add(&kv[3], "ab01", 3,  vtype_val);    /* Hidden */
    kv_add(&kv[4], "ab02", 5,  vtype_val);    /* Seen:   seqno larger than ptomb seqno */
    kv_add(&kv[5], "ab03", 11, vtype_val);    /* Hidden: seqno larger than cursor seqno */
    kv_add(&kv[6], "ab03", 3,  vtype_val);    /* Hidden */
    kv_add(&kv[7], "ab04", 4,  vtype_val);    /* Seen:   pt should NOT hide key */
    kv_add(&kv[8], "ac01", 4,  vtype_val);    /* Seen:   Does not match ptomb's pfx */
    kv_add(&kv[9], "bb01", 4,  vtype_val);    /* Hidden: Does not match cursor pfx */
    kv_end();

    tree.ct_route_map = route_map_create(&cp, "KVS-non-existent-routemap");
    rnode = route_map_insert(tree.ct_route_map, &tn, &ekey, sizeof(ekey), 0);
    ASSERT_NE(NULL, rnode);

    err = cn_tree_cursor_create(&cur);
    ASSERT_EQ(0, err);

    struct kvs_cursor_element elem;
    bool eof = false;

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp("ab", &elem));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp("ab02", &elem));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp("ab04", &elem));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, cmp("ac01", &elem));
    ASSERT_FALSE(eof);

    err = cn_tree_cursor_read(&cur, &elem, &eof);
    ASSERT_EQ(0, err);
    ASSERT_TRUE(eof);

    cn_tree_cursor_destroy(&cur);

    route_map_delete(tree.ct_route_map, rnode);
    route_map_destroy(tree.ct_route_map);
}

MTF_END_UTEST_COLLECTION(cn_tree_cursor_test)
