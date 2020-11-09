/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_c1_tree

#include "c1_private.h"

static u64
c1_tree_get_log_capacity(struct c1_tree *tree);

static merr_t
c1_tree_set_log_capacity(struct c1_tree *tree);

merr_t
c1_tree_create(
    struct mpool *      ds,
    u64                 seqno,
    u32                 gen,
    struct c1_log_desc *desc,
    u64                 mdcoid1,
    u64                 mdcoid2,
    int                 mclass,
    u32                 strip_size,
    u32                 stripe_width,
    u64                 capacity,
    struct c1_tree **   out)

{
    struct c1_tree *tree;

    tree = alloc_aligned(sizeof(*tree), SMP_CACHE_BYTES);
    if (ev(!tree))
        return merr(ENOMEM);

    memset(tree, 0, sizeof(*tree));
    INIT_LIST_HEAD(&tree->c1t_list);
    atomic_set(&tree->c1t_nextlog, 0);
    atomic64_set(&tree->c1t_mutation, 0);
    atomic64_set(&tree->c1t_rsvdspace, 0);
    tree->c1t_capacity = capacity;
    tree->c1t_seqno = seqno;
    tree->c1t_gen = gen;
    tree->c1t_mdcoid1 = mdcoid1;
    tree->c1t_mdcoid2 = mdcoid2;
    tree->c1t_mclass = mclass;
    tree->c1t_strip_size = strip_size;
    tree->c1t_stripe_width = stripe_width;
    tree->c1t_ds = ds;
    tree->c1t_desc = desc;
    tree->c1t_log = NULL;
    atomic64_set(&tree->c1t_numkeys, 0);
    atomic64_set(&tree->c1t_numvals, 0);

    *out = tree;

    return 0;
}

merr_t
c1_tree_destroy(struct mpool *ds, struct c1_log_desc *desc, int numlogs)
{
    merr_t err = 0;
    int    i;

    for (i = 0; i < numlogs; i++) {
        if (desc[i].c1_oid != 0) {
            err = c1_log_destroy(ds, &desc[i]);
            if (ev(err))
                hse_elog(
                    HSE_ERR "%s: Cannot destroy %p log: @@e",
                    err,
                    __func__,
                    (void *)desc[i].c1_oid);
        }
    }

    return err;
}

static merr_t
c1_tree_alloc_impl(struct c1_tree *tree)
{
    struct c1_log_desc *desc;
    u64                 logsize;
    int                 numlogs;
    int                 i;
    merr_t              err;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    logsize = c1_tree_get_log_capacity(tree);
    assert(logsize != 0);

    if (logsize == 0) {
        err = merr(ev(EINVAL));
        hse_elog(HSE_ERR "%s: Invalid log size : @@e", err, __func__);
        return err;
    }

    desc = malloc_array(numlogs, sizeof(*desc));
    if (!desc)
        return merr(ev(ENOMEM));

    memset(desc, 0, numlogs * sizeof(*desc));

    for (i = 0; i < numlogs; i++) {
        err = c1_log_create(tree->c1t_ds, logsize, &tree->c1t_mclass, &desc[i]);
        if (ev(err))
            goto err_exit;
    }

    tree->c1t_desc = desc;
    return 0;

err_exit:

    for (i = 0; i < numlogs; i++)
        if (desc[i].c1_oid != 0)
            c1_log_abort(tree->c1t_ds, &desc[i]);

    free(desc);

    return err;
}

merr_t
c1_tree_alloc(
    struct mpool *   ds,
    u64              seqno,
    u32              gen,
    u64              mdcoid1,
    u64              mdcoid2,
    int *            mclass,
    u32              stripsize,
    u32              stripewidth,
    u64              capacity,
    struct c1_tree **out)
{
    merr_t          err;
    struct c1_tree *tree = NULL;

    err = c1_tree_create(
        ds, seqno, gen, NULL, mdcoid1, mdcoid2, *mclass, stripsize, stripewidth, capacity, &tree);
    if (ev(err))
        return err;

    err = c1_tree_alloc_impl(tree);
    if (ev(err)) {
        free_aligned(tree);
        return err;
    }

    *mclass = tree->c1t_mclass;
    *out = tree;

    return err;
}

merr_t
c1_tree_make(struct c1_tree *tree)
{
    u64    logsize;
    int    numlogs;
    int    i;
    merr_t err;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    assert(tree->c1t_desc != NULL);

    logsize = tree->c1t_capacity / tree->c1t_stripe_width;
    if (logsize < MB)
        return merr(ev(EINVAL));

    logsize = clamp_t(u64, logsize, HSE_C1_MIN_LOG_SIZE, HSE_C1_MAX_LOG_SIZE);

    for (i = 0; i < numlogs; i++) {
        err = c1_log_make(
            tree->c1t_ds,
            tree->c1t_seqno,
            tree->c1t_gen,
            tree->c1t_mdcoid1,
            tree->c1t_mdcoid2,
            &tree->c1t_desc[i],
            logsize);
        if (ev(err))
            goto err_exit;
    }

    return 0;

err_exit:

    while (i >= 0) {
        if (tree->c1t_desc[i].c1_oid != 0)
            c1_log_destroy(tree->c1t_ds, &tree->c1t_desc[i]);
        i--;
    }

    return err;
}

merr_t
c1_tree_open(struct c1_tree *tree, bool replay)
{
    struct c1_log **logp;
    int             i;
    int             numlogs;
    merr_t          err = 0;
    merr_t          err2;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    logp = malloc_array(numlogs, sizeof(*logp));
    if (!logp)
        return merr(ev(ENOMEM));

    tree->c1t_log = logp;

    for (i = 0; i < numlogs; i++)
        logp[i] = NULL;

    for (i = 0; i < numlogs; i++) {
        assert(tree->c1t_desc[i].c1_oid != 0);

        err2 = c1_log_open(
            tree->c1t_ds,
            tree->c1t_seqno,
            tree->c1t_gen,
            tree->c1t_mdcoid1,
            tree->c1t_mdcoid2,
            &tree->c1t_desc[i],
            c1_tree_get_log_capacity(tree),
            &logp[i]);
        if (ev(err2)) {
            hse_elog(
                HSE_ERR "%s: Cannot open %p log: @@e",
                err2,
                __func__,
                (void *)tree->c1t_desc[i].c1_oid);

            err = err2;
            break;
        }

        assert(logp[i] != NULL);
    }

    if (!err && !replay)
        err = c1_tree_set_log_capacity(tree);

    if (ev(err))
        goto err_exit;

    return 0;

err_exit:
    for (i = 0; i < numlogs; i++) {
        if (logp[i]) {
            err2 = c1_log_close(logp[i]);
            if (ev(err2))
                hse_elog(
                    HSE_ERR "%s: Cannot close %p log: @@e",
                    err2,
                    __func__,
                    (void *)tree->c1t_desc[i].c1_oid);
        }
    }

    tree->c1t_log = NULL;

    free(logp);

    return err;
}

static merr_t
c1_tree_close_impl(struct c1_tree *tree)
{
    int    i;
    int    numlogs;
    merr_t err = 0;
    merr_t err2;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    if (!tree->c1t_log)
        numlogs = 0;

    for (i = 0; i < numlogs; i++) {

        assert(tree->c1t_log[i] != NULL);

        err2 = c1_log_close(tree->c1t_log[i]);
        if (ev(err2)) {
            hse_elog(
                HSE_ERR "%s: Cannot close %p log: @@e",
                err2,
                __func__,
                (void *)tree->c1t_desc[i].c1_oid);
            err = err2;
        } else {
            tree->c1t_log[i] = NULL;
        }
    }

    free(tree->c1t_log);
    free(tree->c1t_desc);

    tree->c1t_log = NULL;
    tree->c1t_desc = NULL;

    return err;
}

merr_t
c1_tree_close(struct c1_tree *tree)
{
    merr_t err;

    err = c1_tree_close_impl(tree);
    if (ev(err))
        return err;

    free_aligned(tree);

    return 0;
}

static u64
c1_tree_get_log_capacity(struct c1_tree *tree)
{
    int numlogs;
    u64 logsize;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    logsize = tree->c1t_capacity / numlogs;

    logsize = clamp_t(u64, logsize, HSE_C1_MIN_LOG_SIZE, HSE_C1_MAX_LOG_SIZE);

    return logsize;
}

static merr_t
c1_tree_set_log_capacity(struct c1_tree *tree)
{
    int    i;
    int    numlogs;
    merr_t err = 0;
    u64    logsize;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    logsize = c1_tree_get_log_capacity(tree);
    if (logsize == 0) {
        err = merr(ev(EINVAL));
        hse_elog(HSE_ERR "%s: Invalid log size : @@e", err, __func__);
        return err;
    }

    for (i = 0; i < numlogs; i++) {

        assert(tree->c1t_log[i] != NULL);

        c1_log_set_capacity(tree->c1t_log[i], logsize);
    }

    return 0;
}

merr_t
c1_tree_get_desc(struct c1_tree *tree, struct c1_log_desc **desc, int *numdesc)
{
    if (!tree->c1t_desc)
        return merr(ev(EINVAL));

    *desc = tree->c1t_desc;
    *numdesc = tree->c1t_stripe_width;
    assert(*numdesc >= 0);

    return 0;
}

u64
c1_tree_space_threshold(struct c1_tree *tree)
{
    u64 capacity;

    if (!tree)
        return 0;

    capacity = c1_log_get_capacity(tree->c1t_log[0]);

    return ((HSE_C1_LOG_USEABLE_CAPACITY(capacity)) * 75) / 100;
}

merr_t
c1_tree_reserve_space_txn(struct c1_tree *tree, u64 size)
{
    u64 available;
    u64 reserved;

    available = HSE_C1_TREE_USEABLE_CAPACITY(tree->c1t_capacity);
    if (size > available) {
        hse_log(
            HSE_ERR "c1_tree ingest size 0x%lx exceeded capacity 0x%lx",
            (unsigned long)size,
            (unsigned long)available);

        return merr(ENOSPC);
    }

    reserved = atomic64_add_return(size, &tree->c1t_rsvdspace);

    if (reserved > available) {
        atomic64_sub(size, &tree->c1t_rsvdspace);
        return merr(ENOMEM);
    }

    return 0;
}

void
c1_tree_refresh_space(struct c1_tree *tree)
{
    int i;
    u64 used = 0;

    for (i = 0; i < tree->c1t_stripe_width; i++)
        used += c1_log_refresh_space(tree->c1t_log[i]);

    atomic64_set(&tree->c1t_rsvdspace, used);
}

merr_t
c1_tree_reserve_space(struct c1_tree *tree, u64 rsvsz, int *idx, u64 *mutation, bool spare)
{
    struct c1_log *log;
    int            i;
    int            nextlog;
    int            numlogs;
    merr_t         err;

    numlogs = tree->c1t_stripe_width;
    nextlog = atomic_read(&tree->c1t_nextlog);
    nextlog %= numlogs;

    log = tree->c1t_log[nextlog];

    err = c1_log_reserve_space(log, rsvsz, spare);
    if (!err) {
        *idx = nextlog;
        goto exit_succ;
    }

    if (ev(merr_errno(err) != ENOMEM))
        return err;

    for (i = 0; i < numlogs; i++) {
        if (i == nextlog)
            continue;

        log = tree->c1t_log[i];

        err = c1_log_reserve_space(log, rsvsz, spare);
        if (!err) {
            *idx = i;
            goto exit_succ;
        }

        if (ev(merr_errno(err) != ENOMEM))
            return err;
    }

    return err;

exit_succ:
    *mutation = atomic64_add_return(1, &tree->c1t_mutation);
    atomic_inc(&tree->c1t_nextlog);

    return 0;
}

merr_t
c1_tree_reserve_space_iter(
    struct c1_tree *    tree,
    u32                 kmetasz,
    u32                 vmetasz,
    u32                 kvbmetasz,
    u64                 stripsz,
    struct c1_iterinfo *ci)
{
    int i;
    int nextlog;
    int numlogs;
    u64 rsvdsz[HSE_C1_DEFAULT_STRIPE_WIDTH] = {};

    numlogs = tree->c1t_stripe_width;
    nextlog = atomic_read(&tree->c1t_nextlog);
    nextlog %= numlogs;

    /*
     * Simulate iter distribution across mlogs and determine if
     * there's enough space to hold this mutation set.
     */
    for (i = 0; i < ci->ci_iterc; i++) {
        struct c1_log *log;
        u64            sz;
        u32            kvbc;

        if (ci->ci_iterv[i].ck_kcnt == 0)
            continue;

        log = tree->c1t_log[nextlog];

        sz = ci->ci_iterv[i].ck_kvsz;
        assert(stripsz);
        kvbc = (sz / stripsz) + 1;
        sz +=
            (kmetasz * ci->ci_iterv[i].ck_kcnt + vmetasz * ci->ci_iterv[i].ck_vcnt +
             kvbmetasz * kvbc);

        assert(nextlog < HSE_C1_DEFAULT_STRIPE_WIDTH);
        if (!c1_log_has_space(log, sz, &rsvdsz[nextlog])) {
            int j = (nextlog + 1) % numlogs;

            while (j != nextlog) {
                log = tree->c1t_log[j];

                assert(j < HSE_C1_DEFAULT_STRIPE_WIDTH);
                if (c1_log_has_space(log, sz, &rsvdsz[j]))
                    break;

                j = (j + 1) % numlogs;
            }

            if (j == nextlog)
                return merr(ENOSPC);
        }

        nextlog = (nextlog + 1) % numlogs;
    }

    return 0;
}

merr_t
c1_tree_issue_kvb(
    struct c1_tree *              tree,
    u64                           ingestid,
    u64                           vsize,
    int                           idx,
    u64                           txnid,
    u64                           mutation,
    struct c1_kvbundle *          kvb,
    int                           sync,
    u8                            tidx)
{
    struct c1_log *log;
    u64            seqno;
    u32            gen;

    seqno = tree->c1t_seqno;
    gen = tree->c1t_gen;

    log = tree->c1t_log[idx];

    return c1_log_issue_kvb(
        log, ingestid, vsize, kvb, seqno, txnid, gen, mutation, sync, tidx);
}

merr_t
c1_tree_issue_txn(struct c1_tree *tree, int idx, u64 mutation, struct c1_ttxn *txn, int sync)
{
    struct c1_log *log;
    u64            seqno;
    u32            gen;

    seqno = tree->c1t_seqno;
    gen = tree->c1t_gen;

    log = tree->c1t_log[idx];

    return c1_log_issue_txn(log, txn, seqno, gen, mutation, sync);
}

merr_t
c1_tree_get_complete(struct c1_tree *tree, struct c1_complete *cmp)
{
    int i;
    int numlogs;
    u64 seqno;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    if (!tree->c1t_log || (numlogs <= 0))
        return merr(ev(EINVAL));

    cmp->c1c_kvseqno = C1_INVALID_SEQNO;
    cmp->c1c_seqno = tree->c1t_seqno;
    cmp->c1c_gen = tree->c1t_gen;

    for (i = 0; i < numlogs; i++) {
        seqno = c1_log_kvseqno(tree->c1t_log[i]);
        if (cmp->c1c_kvseqno < seqno)
            cmp->c1c_kvseqno = seqno;
    }

    return 0;
}

BullseyeCoverageSaveOff
merr_t
c1_tree_reset(struct c1_tree *tree, u64 newseqno, u32 newgen)
{
    int    i;
    int    numlogs;
    merr_t err;
    merr_t err2;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);
    err = 0;

    if (!tree->c1t_log || (numlogs <= 0))
        return merr(ev(EINVAL));

    for (i = 0; i < numlogs; i++) {
        err2 = c1_log_reset(tree->c1t_log[i], newseqno, newgen);
        if (ev(err2))
            err = err2;
    }

    if (ev(err))
        return err;

    tree->c1t_seqno = newseqno;
    tree->c1t_gen = newgen;
    atomic64_set(&tree->c1t_rsvdspace, 0);

    err = c1_tree_set_log_capacity(tree);
    if (ev(err))
        return err;

    return 0;
}
BullseyeCoverageRestore

merr_t
c1_tree_flush(struct c1_tree *tree)
{
    int    i;
    int    numlogs;
    merr_t err;
    merr_t err2;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);
    err = 0;

    if (!tree->c1t_log || (numlogs <= 0))
        return merr(ev(EINVAL));

    for (i = 0; i < numlogs; i++) {
        err2 = c1_log_flush(tree->c1t_log[i]);
        if (ev(err2))
            err = err2;
    }

    return err;
}
