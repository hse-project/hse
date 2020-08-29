/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_c1_vbuilder

#include <mpool/mpool.h>

#include <hse_ikvdb/kvset_builder.h>
#include <hse_ikvdb/c0sk.h>

#include "c1_private.h"
#include "c1_vbuilder_internal.h"

struct c1_kvset_builder {
    struct c0sk *    c1kvsb_c0sk;
    struct mutex     c1kvsb_mtx;
    struct list_head c1kvsb_list;
    atomic64_t       c1kvsb_gen;
    atomic64_t       c1kvsb_gen_ingested;
};

struct c1_kvset_builder_elem {
    struct list_head        c1kvsbe_list;
    struct c0sk            *c1kvsbe_c0sk;
    atomic64_t              c1kvsbe_gen;
    u64                     c1kvsbe_sign;

    __aligned(SMP_CACHE_BYTES)
    struct mutex            c1kvsbe_flush_mtx;
    atomic64_t              c1kvsbe_refcnt;
    atomic_t                c1kvsbe_acquired;

    __aligned(SMP_CACHE_BYTES)
    struct kvset_builder   *c1kvsbe_bldrs[HSE_KVS_COUNT_MAX];
    struct rw_semaphore     c1kvsbe_sem[HSE_KVS_COUNT_MAX];
};

merr_t
c1_kvset_builder_create(struct c0sk *c0sk, struct c1_kvset_builder **bldrsout)
{
    struct c1_kvset_builder *bldrs;

    bldrs = malloc(sizeof(*bldrs));
    if (ev(!bldrs))
        return merr(ENOMEM);

    mutex_init(&bldrs->c1kvsb_mtx);
    INIT_LIST_HEAD(&bldrs->c1kvsb_list);
    atomic64_set(&bldrs->c1kvsb_gen, (u64)-1);
    atomic64_set(&bldrs->c1kvsb_gen_ingested, (u64)-1);

    bldrs->c1kvsb_c0sk = c0sk;

    *bldrsout = bldrs;

    return 0;
}

void
c1_kvset_builder_destroy(struct c1_kvset_builder *bldrs)
{
    struct c1_kvset_builder_elem *elem, *elem_tmp;

    if (!bldrs)
        return;

    mutex_lock(&bldrs->c1kvsb_mtx);

    list_for_each_entry_safe (elem, elem_tmp, &bldrs->c1kvsb_list, c1kvsbe_list) {
        c1_kvset_builder_elem_put_int(bldrs, elem, false, true);
    }

    assert(list_empty(&bldrs->c1kvsb_list));
    mutex_unlock(&bldrs->c1kvsb_mtx);

    mutex_destroy(&bldrs->c1kvsb_mtx);

    free(bldrs);
}

static merr_t
c1_kvset_builder_elem_create_int(
    struct c1_kvset_builder *      bldrs,
    u64                            gen,
    struct c1_kvset_builder_elem **elemout)
{
    struct c1_kvset_builder_elem *elem;
    int                           i;

    elem = alloc_aligned(sizeof(*elem), __alignof(*elem), 0);
    if (ev(!elem))
        return merr(ENOMEM);

    elem->c1kvsbe_c0sk = bldrs->c1kvsb_c0sk;

    mutex_init(&elem->c1kvsbe_flush_mtx);
    elem->c1kvsbe_sign = 0xaabbccdd0011eeff;
    INIT_LIST_HEAD(&elem->c1kvsbe_list);
    atomic_set(&elem->c1kvsbe_acquired, 0);
    atomic64_set(&elem->c1kvsbe_refcnt, 2);
    atomic64_set(&elem->c1kvsbe_gen, gen);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        init_rwsem(&elem->c1kvsbe_sem[i]);
        elem->c1kvsbe_bldrs[i] = NULL;
    }

    *elemout = elem;
    atomic64_set(&bldrs->c1kvsb_gen, gen);

    return 0;
}

merr_t
c1_kvset_builder_elem_create(
    struct c1_kvset_builder *      bldrs,
    u64                            gen,
    struct c1_kvset_builder_elem **elemout)
{
    struct c1_kvset_builder_elem *elem;
    merr_t                        err;
    u64                           gen_ingested;

    elem = NULL;

    gen_ingested = atomic64_read(&bldrs->c1kvsb_gen_ingested);

    if ((gen_ingested != (u64)-1) && (gen <= gen_ingested)) {
        *elemout = NULL;
        return 0;
    }

    mutex_lock(&bldrs->c1kvsb_mtx);

    gen_ingested = atomic64_read(&bldrs->c1kvsb_gen_ingested);
    if ((gen_ingested != (u64)-1) && (gen <= gen_ingested)) {
        mutex_unlock(&bldrs->c1kvsb_mtx);
        *elemout = NULL;
        return 0;
    }

    err = c1_kvset_builder_elem_get_int(bldrs, gen, &elem);
    if (!err) {
        /*
         * If the vbuilder is handed over to c0sk_ingest_worker then
         * release it. c1_log_issue_kvb will use mlogs until cn_ingestv
         * gets completed.
         */
        if (c1_kvset_builder_abort_ingest(elem)) {
            c1_kvset_builder_elem_put_int(bldrs, elem, false, false);
            *elemout = NULL;
        } else {
            *elemout = elem;
        }
        mutex_unlock(&bldrs->c1kvsb_mtx);

        return 0;
    }

    err = c1_kvset_builder_elem_create_int(bldrs, gen, &elem);
    if (!ev(err))
        list_add_tail(&elem->c1kvsbe_list, &bldrs->c1kvsb_list);

    mutex_unlock(&bldrs->c1kvsb_mtx);

    *elemout = elem;

    return err;
}

static void
c1_kvset_builder_elem_destroy(struct c1_kvset_builder_elem *elem)
{
    struct kvset_builder **bldrs;
    struct c0sk *          c0sk;
    int                    i;

    if (!atomic_read(&elem->c1kvsbe_acquired)) {
        bldrs = elem->c1kvsbe_bldrs;
        c0sk = elem->c1kvsbe_c0sk;
    } else {
        bldrs = NULL;
        c0sk = NULL;
    }

    mutex_destroy(&elem->c1kvsbe_flush_mtx);
    elem->c1kvsbe_sign = (u64)-1;

    if (bldrs) {
        /*
         * [HSE_REVISIT] Not expected to reach here. If we are here,
         * we need to delete or abort mblocks to avoid leak.
         */
        for (i = 0; i < HSE_KVS_COUNT_MAX; i++)
            if (bldrs[i])
                c0sk_kvset_builder_destroy(c0sk, bldrs[i]);
    }

    free_aligned(elem);
}

void
c1_kvset_builder_elem_put_int(
    struct c1_kvset_builder *     bldrs,
    struct c1_kvset_builder_elem *elem,
    bool                          need_lock,
    bool                          final)
{
    u64 refcnt;

    assert(atomic64_read(&elem->c1kvsbe_refcnt) >= 1);
    refcnt = atomic64_dec_return(&elem->c1kvsbe_refcnt);

    if (!refcnt || final) {

        if (need_lock) {
            mutex_lock(&bldrs->c1kvsb_mtx);
            if (atomic64_read(&elem->c1kvsbe_refcnt) != 0) {
                mutex_unlock(&bldrs->c1kvsb_mtx);
                return;
            }
        }

        list_del(&elem->c1kvsbe_list);
        c1_kvset_builder_elem_destroy(elem);

        if (need_lock)
            mutex_unlock(&bldrs->c1kvsb_mtx);
    }
}

void
c1_kvset_builder_elem_put(struct c1_kvset_builder *bldrs, struct c1_kvset_builder_elem *elem)
{
    assert(elem);
    c1_kvset_builder_elem_put_int(bldrs, elem, true, false);
}

merr_t
c1_kvset_builder_elem_get_int(
    struct c1_kvset_builder *      bldrs,
    u64                            gen,
    struct c1_kvset_builder_elem **elemout)
{
    struct c1_kvset_builder_elem *elem;
    bool                          found;

    found = false;
    list_for_each_entry (elem, &bldrs->c1kvsb_list, c1kvsbe_list) {
        if (atomic64_read(&elem->c1kvsbe_gen) == gen) {
            assert(elem->c1kvsbe_sign == 0xaabbccdd0011eeff);
            atomic64_inc(&elem->c1kvsbe_refcnt);
            found = true;
            break;
        }
    }

    if (!found)
        return merr(ENOENT);

    *elemout = elem;

    return 0;
}

merr_t
c1_kvset_builder_elem_get(
    struct c1_kvset_builder *      bldrs,
    u64                            gen,
    struct c1_kvset_builder_elem **elemout)
{
    merr_t err;

    mutex_lock(&bldrs->c1kvsb_mtx);
    err = c1_kvset_builder_elem_get_int(bldrs, gen, elemout);
    mutex_unlock(&bldrs->c1kvsb_mtx);

    return err;
}

bool
c1_kvset_builder_elem_valid(struct c1_kvset_builder_elem *elem, u64 gen)
{
    return atomic64_read(&elem->c1kvsbe_gen) == gen;
}

merr_t
c1_kvset_vbuilder_acquire(struct c1_kvset_builder *bldrs, u64 gen, struct kvset_builder ***bldrout)
{
    struct c1_kvset_builder_elem *elem;
    struct kvset_builder *        bldr;
    merr_t                        err;
    int                           i;
    int                           acquired;

    assert(
        (atomic64_read(&bldrs->c1kvsb_gen_ingested) == (u64)-1) ||
        (atomic64_read(&bldrs->c1kvsb_gen_ingested) < gen));

    atomic64_set(&bldrs->c1kvsb_gen_ingested, gen);

    elem = NULL;
    err = c1_kvset_builder_elem_get(bldrs, gen, &elem);
    if (err) {
        ev(merr_errno(err) != ENOENT);
        return err;
    }

    assert(elem);
    assert(atomic64_read(&elem->c1kvsbe_gen) == gen);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++)
        down_write(&elem->c1kvsbe_sem[i]);

    acquired = atomic_inc_return(&elem->c1kvsbe_acquired);

    if (ev(acquired != 1)) {
        hse_log(HSE_ERR "c1 vbldr is already acquired  for genno %ld", (unsigned long)gen);

        c1_kvset_builder_elem_put(bldrs, elem);
        while (--i >= 0)
            up_write(&elem->c1kvsbe_sem[i]);

        return merr(EINVAL);
    }

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        bldr = elem->c1kvsbe_bldrs[i];
        if (err || !bldr) {
            up_write(&elem->c1kvsbe_sem[i]);
            continue;
        }

        err = ev(c0sk_kvset_builder_flush(elem->c1kvsbe_c0sk, bldr));
        up_write(&elem->c1kvsbe_sem[i]);
    }

    if (ev(err))
        return err;

    *bldrout = elem->c1kvsbe_bldrs;

    return 0;
}

void
c1_kvset_vbuilder_release(struct c1_kvset_builder *bldrs, u64 gen)
{
    struct c1_kvset_builder_elem *elem;
    merr_t                        err;

    elem = NULL;
    err = c1_kvset_builder_elem_get(bldrs, gen, &elem);
    if (ev(err)) {
        hse_elog(
            HSE_ERR "%s: Cannot find vbldr with gen %ld : @@e", err, __func__, (unsigned long)gen);

        assert(0);
        return;
    }

    assert(elem);
    assert(atomic64_read(&elem->c1kvsbe_gen) == gen);

    /*
     * Get rid of the refence by c1_kvset_builder_elem_get here.
     */
    c1_kvset_builder_elem_put(bldrs, elem);

    /*
     * Get rid of the refence by c1_kvset_vbuilder_acquire
     */
    c1_kvset_builder_elem_put(bldrs, elem);

    /*
     * Give up the final refernece and release it.
     */
    c1_kvset_builder_elem_put(bldrs, elem);
}

merr_t
c1_kvset_builder_flush(struct c1_kvset_builder *bldrs)
{
    struct kvset_builder *        bldr;
    struct c1_kvset_builder_elem *elem;
    merr_t                        err;
    int                           i;
    u64                           gen;

    gen = atomic64_read(&bldrs->c1kvsb_gen);
    if (gen == (u64)-1)
        return 0;

    err = c1_kvset_builder_elem_get(bldrs, gen, &elem);
    if (err) {
        ev(merr_errno(err) != ENOENT);
        return err;
    }

    mutex_lock(&elem->c1kvsbe_flush_mtx);

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {
        down_write(&elem->c1kvsbe_sem[i]);
        bldr = elem->c1kvsbe_bldrs[i];
        if (!bldr || c1_kvset_builder_abort_ingest(elem)) {
            up_write(&elem->c1kvsbe_sem[i]);
            continue;
        }

        err = c0sk_kvset_builder_flush(elem->c1kvsbe_c0sk, bldr);
        up_write(&elem->c1kvsbe_sem[i]);
        if (ev(err))
            break;
    }
    mutex_unlock(&elem->c1kvsbe_flush_mtx);

    c1_kvset_builder_elem_put(bldrs, elem);

    return err;
}

merr_t
c1_kvset_builder_flush_elem(struct c1_kvset_builder_elem *bldrs, u8 index)
{
    struct kvset_builder *bldr;

    int    i;
    merr_t err;

    for (i = 0; i < HSE_KVS_COUNT_MAX; i++) {

        down_read(&bldrs->c1kvsbe_sem[i]);
        bldr = bldrs->c1kvsbe_bldrs[i];
        if (!bldr) {
            up_read(&bldrs->c1kvsbe_sem[i]);
            continue;
        }

        if (c1_kvset_builder_abort_ingest(bldrs)) {
            up_read(&bldrs->c1kvsbe_sem[i]);
            return 0;
        }

        err = kvset_builder_finish_vblock(bldr, index);
        up_read(&bldrs->c1kvsbe_sem[i]);

        if (ev(err))
            return err;
    }

    return 0;
}

bool
c1_kvset_builder_abort_ingest(struct c1_kvset_builder_elem *bldrs)
{
    return atomic_read(&bldrs->c1kvsbe_acquired);
}

merr_t
c1_kvset_builder_add_val(
    struct c1_kvset_builder_elem *bldrs,
    u32                           skidx,
    u64                           cnid,
    u64                           seqno,
    void *                        vdata,
    u64                           vlen,
    u8                            tidx,
    u64 *                         vbgenout,
    u64 *                         vbidout,
    u32 *                         vbidxout,
    u32 *                         vboffout,
    struct kvset_builder **       vbkvsbldrout)
{
    struct kvset_builder *bldr;
    merr_t                err = 0;

    assert(skidx < HSE_KVS_COUNT_MAX);

    /* Set the no. of c1 vblocks to half the no. of c1 threads. With this,
     * 4 c1 threads share 2 vblocks and this improves vblock utilization.
     */
    tidx /= 2;
    down_read(&bldrs->c1kvsbe_sem[skidx]);

    bldr = bldrs->c1kvsbe_bldrs[skidx];
    if (!bldr) {
        up_read(&bldrs->c1kvsbe_sem[skidx]);

        down_write(&bldrs->c1kvsbe_sem[skidx]);
        if (ev(c1_kvset_builder_abort_ingest(bldrs))) {
            up_write(&bldrs->c1kvsbe_sem[skidx]);
            return merr(EIO);
        }

        bldr = bldrs->c1kvsbe_bldrs[skidx];
        if (!bldr) {
            err = c0sk_kvset_builder_create(bldrs->c1kvsbe_c0sk, skidx, &bldr);
            if (ev(err)) {
                up_write(&bldrs->c1kvsbe_sem[skidx]);
                return err;
            }
            bldrs->c1kvsbe_bldrs[skidx] = bldr;
        }
        up_write(&bldrs->c1kvsbe_sem[skidx]);

        down_read(&bldrs->c1kvsbe_sem[skidx]);
    }

    if (c1_kvset_builder_abort_ingest(bldrs)) {
        up_read(&bldrs->c1kvsbe_sem[skidx]);
        return merr_once(EIO);
    }

    *vbkvsbldrout = bldr;

    *vbgenout = atomic64_read(&bldrs->c1kvsbe_gen);
    err = kvset_builder_add_val_ext(
        bldr, seqno, vdata, vlen, false, tidx, vbidout, vbidxout, vboffout);
    up_read(&bldrs->c1kvsbe_sem[skidx]);

    /*
     * Any error other than EAGAIN is a hard error from this layer. EAGAIN
     * is used to repeat kvset_builder_add_val_ext with an exclusive lock.
     */
    if (merr_errno(err) != EAGAIN)
        return err;

    down_write(&bldrs->c1kvsbe_sem[skidx]);

    if (ev(c1_kvset_builder_abort_ingest(bldrs))) {
        up_write(&bldrs->c1kvsbe_sem[skidx]);
        return merr(EIO);
    }

    *vbgenout = atomic64_read(&bldrs->c1kvsbe_gen);
    err = kvset_builder_add_val_ext(
        bldr, seqno, vdata, vlen, true, tidx, vbidout, vbidxout, vboffout);
    up_write(&bldrs->c1kvsbe_sem[skidx]);

    return err;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_vbuilder_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
