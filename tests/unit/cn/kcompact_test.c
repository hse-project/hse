/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <stdint.h>

#include <hse/ikvdb/kvs_rparams.h>
#include <hse/ikvdb/kvset_builder.h>
#include <hse/ikvdb/tuple.h>
#include <hse/util/platform.h>
#include <hse/util/slab.h>

#include <hse/test/mock/api.h>
#include <hse/test/mock/mock_kvset.h>
#include <hse/test/mock/mock_kvset_builder.h>
#include <hse/test/mtf/framework.h>

#include "cn/cn_metrics.h"
#include "cn/cn_tree_compact.h"
#include "cn/kcompact.h"
#include "cn/kvset.h"
#include "cn/vgmap.h"

/*
 * The functions with leading underscores are the mocked variants.
 *
 * We need to mock both cn_tree and kvset here, to control the
 * data generated, and to avoid invoking undesired parts of the machinery.
 *
 * The idea of this mock is to replicate the omf log as an in-core array,
 * with readers simply reading from this log, and writers laying down
 * a parallel log for comparison.
 */

int
init(struct mtf_test_info *info);
int
pre(struct mtf_test_info *info);

/* Set to 1 to trace keys emerging from kvset iterators */
extern int mock_kvset_verbose;

/* set to true to disable overly strict check on value size */
bool mixed = false;

#define ITER_MAX 32

struct kv_iterator *itv[ITER_MAX];

int
mixed_pre(struct mtf_test_info *info)
{
    mixed = true;
    return pre(info);
}

int
mixed_post(struct mtf_test_info *info)
{
    mixed = false;
    return 0;
}

static struct cn_compaction_work *
init_work(
    struct cn_compaction_work *w,
    struct mpool *ds,
    struct kvs_rparams *rp,
    uint kvset_cnt,
    struct kv_iterator **inputv,
    atomic_int *cancel,
    struct kvset_mblocks *outv,
    struct cn_tree_node **output_nodev,
    uint64_t *kvsetidv,
    struct kvset_vblk_map *vbmap,
    struct vgmap **vgmap)
{
    w->cw_mp = ds;
    w->cw_rp = rp;
    w->cw_kvset_cnt = kvset_cnt;
    w->cw_inputv = inputv;
    w->cw_cancel_request = cancel;
    w->cw_outv = outv;
    w->cw_output_nodev = output_nodev;
    w->cw_kvsetidv = kvsetidv;
    w->cw_vbmap = *vbmap;
    w->cw_vgmap = vgmap;
    w->cw_input_vgroups = (*vgmap)->nvgroups;

    return w;
}

/* ------------------------------------------------------------
 * Unit tests
 */

MTF_BEGIN_UTEST_COLLECTION_PRE(kcompact_test, init);

struct state {
    int kwant;
    int vwant;
    int src;
    struct {
        const struct key_obj *kobj;
        uint nvals;
        enum kmd_vtype vtype;
        uint vbidx;
        uint vboff;
        uint vlen;
        int value;
    } have;
};

struct state st;

static int
verify(struct kvset_builder *bld)
{
    const struct key_obj *kobj = st.have.kobj;
    int kdata;
    uint klen;

    uint nvals = st.have.nvals;
    enum kmd_vtype vtype = st.have.vtype;
    uint vlen = st.have.vlen;

    VERIFY_TRUE_RET(kobj, __LINE__);

    key_obj_copy(&kdata, sizeof(kdata), &klen, kobj);
    VERIFY_TRUE_RET(st.kwant == kdata, __LINE__);

    VERIFY_TRUE_RET(nvals == 1, __LINE__);

    if (st.vwant == -1) {
        VERIFY_TRUE_RET(vtype == VTYPE_TOMB, __LINE__);
    } else {
        VERIFY_TRUE_RET((vtype == VTYPE_UCVAL) || (vtype == VTYPE_IVAL), __LINE__);
        if (vlen == 4)
            VERIFY_EQ_RET(st.vwant, st.have.value, __LINE__);
        if (!mixed)
            VERIFY_EQ_RET(sizeof(int), vlen, __LINE__);
    }

    /* consume the data */
    ++st.kwant;
    if (st.vwant != -1)
        ++st.vwant;

    return 0;
}

static merr_t
_kvset_builder_add_key(struct kvset_builder *builder, const struct key_obj *kobj)
{
    merr_t err;

    VERIFY_EQ_RET(st.have.kobj, NULL, __LINE__);
    VERIFY_NE_RET(st.have.nvals, 0, __LINE__);

    st.have.kobj = kobj;

    err = verify(builder);
    VERIFY_EQ_RET(err, 0, __LINE__);

    memset(&st.have, 0, sizeof(st.have));
    return 0;
}

static merr_t
_kvset_builder_add_vref(
    struct kvset_builder *self,
    uint64_t seq,
    uint vbidx,
    uint vboff,
    uint vlen,
    uint complen)
{
    VERIFY_EQ_RET(st.have.nvals, 0, __LINE__);

    st.have.nvals++;
    st.have.vtype = VTYPE_UCVAL;
    st.have.vlen = vlen;
    if (vlen == 4)
        st.have.value = *(int *)mock_vref_to_vdata(itv[vbidx], vboff);
    else
        st.have.value = 0;

    return 0;
}

static merr_t
_kvset_builder_add_nonval(struct kvset_builder *self, uint64_t seq, enum kmd_vtype vtype)
{
    VERIFY_EQ_RET(st.have.nvals, 0, __LINE__);

    st.have.nvals++;
    st.have.vtype = vtype;
    st.have.vlen = 0;

    return 0;
}

static merr_t
_kvset_builder_add_val(
    struct kvset_builder *self,
    const struct key_obj *kobj,
    const void *vdata,
    uint vlen,
    uint64_t seq,
    uint complen)
{
    VERIFY_EQ_RET(st.have.nvals, 0, __LINE__);

    st.have.nvals++;
    st.have.vtype = VTYPE_UCVAL;
    st.have.vlen = vlen;
    if (vlen == 4)
        st.have.value = *(int *)vdata;
    else
        st.have.value = 0;

    return 0;
}

MTF_DEFINE_UTEST_PRE(kcompact_test, keep, pre)
{
#define NITER 32
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvset_vblk_map vbmap = { 0 };
    struct vgmap *vgmap;
    int i, j;
    merr_t err;

    memset(itv, 0, sizeof(itv));

    /* 0..NITER vblocks */
    for (i = 0; i < NITER; ++i)
        ASSERT_EQ(0, mock_make_vblocks(&itv[i], &rp, i));

    err = kvset_keep_vblocks(&vbmap, &vgmap, itv, NITER);
    ASSERT_EQ(err, 0);

    /* verify each map is cumulative of what came before */
    for (j = i = 0; i < NITER; ++i) {
        ASSERT_EQ(vbmap.vbm_map[i], j);
        j += i;
    }

    free(vbmap.vbm_blkv);
    vgmap_free(vgmap);
    for (i = 0; i < NITER; ++i) {
        struct mock_kv_iterator *iter = container_of(itv[i], typeof(*iter), kvi);

        kvset_put_ref((struct kvset *)iter->kvset);
        kvset_iter_release(itv[i]);
    }
#undef NITER
}

MTF_DEFINE_UTEST_PRE(kcompact_test, four_into_one, pre)
{
#define NITER 4
    struct cn_compaction_work w = { 0 };
    struct kvset_vblk_map vbmap = { 0 };
    struct vgmap *vgmap, *vgmap2;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvset_mblocks output = {};
    struct cn_tree_node *output_node = NULL;
    uint64_t kvsetidv = 1;
    struct nkv_tab nkv;
    atomic_int c;
    uint64_t dgen = 0;
    int i;
    merr_t err;

    memset(itv, 0, sizeof(itv));
    atomic_set(&c, 0);

    /*
     * 10 keys from 1..10, values from i*100..i*100+10
     * requirement: newest kvset is lowest index
     */
    nkv.nkeys = 10;
    nkv.key1 = 1;
    nkv.be = KVDATA_INT_KEY;
    for (i = 0; i < NITER; ++i) {
        nkv.dgen = ++dgen;
        nkv.val1 = i * 100;
        nkv.vmix = VMX_S32;
        ASSERT_EQ(0, mock_make_kvi(&itv[i], i, &rp, &nkv));
    }

    err = kvset_keep_vblocks(&vbmap, &vgmap, itv, NITER);
    ASSERT_EQ(0, err);

    st.kwant = 1;
    st.vwant = 0;
    st.src = 0; /* the lowest should always be the src */

    init_work(
        &w, (struct mpool *)1, &rp, NITER, itv, &c, &output, &output_node, &kvsetidv, &vbmap,
        &vgmap);

    vgmap2 = vgmap;
    err = cn_kcompact(&w);
    ASSERT_EQ(0, err);

    ASSERT_EQ(w.cw_vbmap.vbm_used, 10 * sizeof(int));
    ASSERT_EQ(w.cw_vbmap.vbm_waste, 30 * sizeof(int));

    ASSERT_EQ(w.cw_stats.ms_srcs, NITER);
    ASSERT_EQ(w.cw_stats.ms_keys_in, 10 * NITER);
    ASSERT_EQ(w.cw_stats.ms_keys_out, 10);
    ASSERT_EQ(w.cw_stats.ms_val_bytes_out, 10 * sizeof(int));

    free(output.vblks.idv);
    for (i = 0; i < NITER; ++i) {
        struct mock_kv_iterator *iter = container_of(itv[i], typeof(*iter), kvi);

        kvset_put_ref((struct kvset *)iter->kvset);
        kvset_iter_release(itv[i]);
    }

    free(vbmap.vbm_blkv);
    vgmap_free(vgmap2);
#undef NITER
}

MTF_DEFINE_UTEST_PRE(kcompact_test, all_gone, pre)
{
    struct cn_compaction_work w = { 0 };
    struct kvset_vblk_map vbmap = { 0 };
    struct vgmap *vgmap, *vgmap2;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvset_mblocks output = {};
    struct cn_tree_node *output_node = NULL;
    uint64_t kvsetidv = 1;
    struct kv_iterator *itv[5] = { 0 };
    struct nkv_tab nkv;
    atomic_int c;
    uint64_t dgen = 0;
    int i;
    merr_t err;

    atomic_set(&c, 0);

    /*
     * tombstones in the first: should annihilate all
     * 10 keys from 1..10, values from i*100..i*100+10
     * requirement: newest kvset is lowest index
     */
    nkv.nkeys = 10;
    nkv.key1 = 1;
    nkv.be = KVDATA_INT_KEY;
    nkv.dgen = ++dgen;
    nkv.val1 = -1;
    ASSERT_EQ(0, mock_make_kvi(&itv[0], 0, &rp, &nkv));
    for (i = 1; i < 5; ++i) {
        nkv.val1 = i * 100;
        nkv.vmix = VMX_S32;
        nkv.dgen = ++dgen;
        ASSERT_EQ(0, mock_make_kvi(&itv[i], i, &rp, &nkv));
    }

    err = kvset_keep_vblocks(&vbmap, &vgmap, itv, 5);
    ASSERT_EQ(0, err);

    /* HSE_REVISIT: is it possible to detect a memory overwrite here? */

    st.kwant = 1;
    st.vwant = -1; /* -1 == tombstones */
    st.src = 0;    /* the lowest should always be the src */

    init_work(
        &w, (struct mpool *)1, &rp, 5, itv, &c, &output, &output_node, &kvsetidv, &vbmap, &vgmap);

    vgmap2 = vgmap;
    err = cn_kcompact(&w);
    ASSERT_EQ(0, err);

    ASSERT_EQ(w.cw_vbmap.vbm_used, 0);
    ASSERT_EQ(w.cw_vbmap.vbm_waste, 10 * 4 * sizeof(int));

    ASSERT_EQ(w.cw_stats.ms_srcs, 5);
    ASSERT_EQ(w.cw_stats.ms_keys_in, 10 * 5);
    ASSERT_EQ(w.cw_stats.ms_keys_out, 10);
    ASSERT_EQ(w.cw_stats.ms_val_bytes_out, 0);

    free(output.vblks.idv);
    for (i = 0; i < 5; ++i) {
        struct mock_kv_iterator *iter = container_of(itv[i], typeof(*iter), kvi);

        kvset_put_ref((struct kvset *)iter->kvset);
        kvset_iter_release(itv[i]);
    }

    free(vbmap.vbm_blkv);
    vgmap_free(vgmap2);
}

MTF_DEFINE_UTEST_PREPOST(kcompact_test, all_gone_mixed, mixed_pre, mixed_post)
{
    struct cn_compaction_work w = { 0 };
    struct kvset_vblk_map vbmap = { 0 };
    struct vgmap *vgmap, *vgmap2;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvset_mblocks output = {};
    struct cn_tree_node *output_node = NULL;
    uint64_t kvsetidv = 1;
    struct kv_iterator *itv[5] = { 0 };
    struct nkv_tab nkv;
    atomic_int c;
    uint64_t dgen = 0;
    int i;
    merr_t err;

    atomic_set(&c, 0);

    /*
     * tombstones in the first: should annihilate all
     * 10 keys from 1..10, values from i*100..i*100+10
     * requirement: newest kvset is lowest index
     */
    nkv.nkeys = 10;
    nkv.key1 = 1;
    nkv.be = KVDATA_INT_KEY;
    nkv.dgen = ++dgen;
    nkv.val1 = -1;
    ASSERT_EQ(0, mock_make_kvi(&itv[0], 0, &rp, &nkv));
    for (i = 1; i < 5; ++i) {
        nkv.val1 = i * 100;
        nkv.vmix = VMX_MIXED;
        nkv.dgen = ++dgen;
        ASSERT_EQ(0, mock_make_kvi(&itv[i], i, &rp, &nkv));
    }

    err = kvset_keep_vblocks(&vbmap, &vgmap, itv, 5);
    ASSERT_EQ(0, err);

    /* HSE_REVISIT: is it possible to detect a memory overwrite here? */

    st.kwant = 1;
    st.vwant = -1; /* -1 == tombstones */
    st.src = 0;    /* the lowest should always be the src */

    init_work(
        &w, (struct mpool *)1, &rp, 5, itv, &c, &output, &output_node, &kvsetidv, &vbmap, &vgmap);

    vgmap2 = vgmap;
    err = cn_kcompact(&w);
    ASSERT_EQ(0, err);

    ASSERT_EQ(w.cw_vbmap.vbm_used, 0);
    ASSERT_EQ(w.cw_vbmap.vbm_waste, 10 * 4 * sizeof(int));

    ASSERT_EQ(w.cw_stats.ms_srcs, 5);
    ASSERT_EQ(w.cw_stats.ms_keys_in, 10 * 5);
    ASSERT_EQ(w.cw_stats.ms_keys_out, 10);
    ASSERT_EQ(w.cw_stats.ms_val_bytes_out, 0);

    free(output.vblks.idv);
    for (i = 0; i < 5; ++i) {
        struct mock_kv_iterator *iter = container_of(itv[i], typeof(*iter), kvi);

        kvset_put_ref((struct kvset *)iter->kvset);
        kvset_iter_release(itv[i]);
    }

    free(vbmap.vbm_blkv);
    vgmap_free(vgmap2);
}

MTF_DEFINE_UTEST_PREPOST(kcompact_test, four_into_one_mixed, mixed_pre, mixed_post)
{
#define NITER 4
    struct cn_compaction_work w = { 0 };
    struct kvset_vblk_map vbmap = { 0 };
    struct vgmap *vgmap, *vgmap2;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvset_mblocks output = {};
    struct cn_tree_node *output_node = NULL;
    uint64_t kvsetidv = 1;
    struct nkv_tab nkv;
    atomic_int c;
    uint64_t dgen = 0;
    int i;
    merr_t err;

    memset(itv, 0, sizeof(itv));
    atomic_set(&c, 0);

    /*
     * 200 keys from 1..200, values from i*1000..i*1000+200
     * requirement: newest kvset is lowest index
     */
    nkv.nkeys = 200;
    nkv.key1 = 1;
    nkv.be = KVDATA_INT_KEY;
    for (i = 0; i < NITER; ++i) {
        nkv.dgen = ++dgen;
        nkv.val1 = i * 1000;
        nkv.vmix = VMX_MIXED;
        ASSERT_EQ(0, mock_make_kvi(&itv[i], i, &rp, &nkv));
    }

    err = kvset_keep_vblocks(&vbmap, &vgmap, itv, NITER);
    ASSERT_EQ(0, err);

    st.kwant = 1;
    st.vwant = 0;
    st.src = 0; /* the lowest should always be the src */

    init_work(
        &w, (struct mpool *)1, &rp, NITER, itv, &c, &output, &output_node, &kvsetidv, &vbmap,
        &vgmap);

    vgmap2 = vgmap;
    err = cn_kcompact(&w);
    ASSERT_EQ(0, err);

    ASSERT_EQ(w.cw_stats.ms_srcs, NITER);
    ASSERT_EQ(w.cw_stats.ms_keys_in, 200 * NITER);
    ASSERT_EQ(w.cw_stats.ms_keys_out, 200);

    free(output.vblks.idv);
    for (i = 0; i < NITER; ++i) {
        struct mock_kv_iterator *iter = container_of(itv[i], typeof(*iter), kvi);

        kvset_put_ref((struct kvset *)iter->kvset);
        kvset_iter_release(itv[i]);
    }

    free(vbmap.vbm_blkv);
    vgmap_free(vgmap2);
#undef NITER
}

int
run_kcompact(struct mtf_test_info *lcl_ti, int expect)
{
    struct cn_compaction_work w = { 0 };
    struct kvset_vblk_map vbmap = { 0 };
    struct vgmap *vgmap, *vgmap2;
    struct kvs_rparams rp = kvs_rparams_defaults();
    struct kvset_mblocks output = {};
    struct cn_tree_node *output_node = NULL;
    uint64_t kvsetidv = 1;
    struct kv_iterator *itv[5] = { 0 };
    struct nkv_tab nkv;
    atomic_int c;
    uint64_t dgen = 0;
    int i;
    merr_t err;

    atomic_set(&c, 0);

    /*
     * tombstones in the first: should annihilate all
     * 10 keys from 1..10, values from i*100..i*100+10
     * requirement: newest kvset is lowest index
     */
    nkv.nkeys = 10;
    nkv.key1 = 1;
    nkv.be = KVDATA_INT_KEY;
    nkv.dgen = ++dgen;
    nkv.val1 = -1;
    ASSERT_EQ_RET(0, mock_make_kvi(&itv[0], 0, &rp, &nkv), 1);
    for (i = 1; i < 5; ++i) {
        nkv.val1 = i * 100;
        nkv.vmix = VMX_MIXED;
        nkv.dgen = ++dgen;
        ASSERT_EQ_RET(0, mock_make_kvi(&itv[i], i, &rp, &nkv), 1);
    }

    err = kvset_keep_vblocks(&vbmap, &vgmap, itv, 5);
    ASSERT_EQ_RET(err, 0, 1);

    /* HSE_REVISIT: is it possible to detect a memory overwrite here? */

    st.kwant = 1;
    st.vwant = -1; /* -1 == tombstones */
    st.src = 0;    /* the lowest should always be the src */

    init_work(
        &w, (struct mpool *)1, &rp, 5, itv, &c, &output, &output_node, &kvsetidv, &vbmap, &vgmap);

    vgmap2 = vgmap;
    err = cn_kcompact(&w);

    if (expect == -1)
        ASSERT_TRUE_RET(err, 1);
    else
        ASSERT_EQ_RET(err, expect, 1);

    free(output.vblks.idv);
    for (i = 0; i < 5; ++i) {
        struct mock_kv_iterator *iter = container_of(itv[i], typeof(*iter), kvi);

        kvset_put_ref((struct kvset *)iter->kvset);
        kvset_iter_release(itv[i]);
    }

    free(vbmap.vbm_blkv);
    vgmap_free(vgmap2);

    return 0;
}

MTF_DEFINE_UTEST_PRE(kcompact_test, kcompact_fail, pre)
{
    uint32_t api;

    if (run_kcompact(lcl_ti, 0))
        return;

    api = mapi_idx_kvset_builder_get_mblocks;
    mapi_inject(api, 123);
    if (run_kcompact(lcl_ti, 123))
        return;
    mapi_inject_unset(api);

    api = mapi_idx_kvset_builder_add_key;
    mapi_inject(api, 123);
    if (run_kcompact(lcl_ti, 123))
        return;
    mapi_inject_unset(api);

    api = mapi_idx_kvset_builder_add_nonval;
    mapi_inject(api, 123);
    if (run_kcompact(lcl_ti, 123))
        return;
    mapi_inject_unset(api);
}

MTF_END_UTEST_COLLECTION(kcompact_test)

int
init(struct mtf_test_info *info)
{
    return 0;
}

uint16_t
_vgmap_vbidx_out_end(struct kvset *ks, uint32_t vgidx)
{
    return kvset_get_num_vblocks(ks) - 1;
}

uint32_t
_kvset_get_vgroups(const struct kvset *ks)
{
    return kvset_get_num_vblocks((struct kvset *)ks) == 0 ? 0 : 1;
}

int
pre(struct mtf_test_info *info)
{
    /* Default mock. */
    mock_kvset_set();
    mock_kvset_builder_set();

    /* Must call these after mock_kvset_builder_set() */
    MOCK_SET(kvset_builder, _kvset_builder_add_key);
    MOCK_SET(kvset_builder, _kvset_builder_add_val);
    MOCK_SET(kvset_builder, _kvset_builder_add_nonval);
    MOCK_SET(kvset_builder, _kvset_builder_add_vref);
    MOCK_SET(kvset, _vgmap_vbidx_out_end);
    MOCK_SET(kvset, _kvset_get_vgroups);

    /* Neuter the following APIs */
    mapi_inject(mapi_idx_cn_tree_get_cn, 0);
    mapi_inject(mapi_idx_cn_tree_get_cndb, 0);
    mapi_inject(mapi_idx_cndb_kvsetid_mint, 1);
    mapi_inject(mapi_idx_kvset_builder_set_agegroup, 0);
    mapi_inject(mapi_idx_kvset_builder_set_merge_stats, 0);

    return 0;
}
