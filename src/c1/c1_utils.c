/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_omf_internal.h"

#include <mpool/mpool.h>

static void
c1_cache_add(struct c1 *c1, struct c1_tree *tree)
{
    mutex_lock(&c1->c1_list_mtx);
    list_add_tail(&tree->c1t_list, &c1->c1_tree_new);
    mutex_unlock(&c1->c1_list_mtx);
}

static bool
c1_cache_remove(struct c1 *c1)
{
    struct c1_tree *tree;

    mutex_lock(&c1->c1_list_mtx);
    if (list_empty(&c1->c1_tree_new)) {
        mutex_unlock(&c1->c1_list_mtx);
        return false;
    }

    tree = list_first_entry_or_null(&c1->c1_tree_new, typeof(*tree), c1t_list);
    assert(tree != NULL);

    list_del(&tree->c1t_list);
    mutex_unlock(&c1->c1_list_mtx);

    mutex_lock(&c1->c1_active_mtx);
    atomic_inc(&c1->c1_active_cnt);
    list_add_tail(&tree->c1t_list, &c1->c1_tree_inuse);
    mutex_unlock(&c1->c1_active_mtx);

    return true;
}

merr_t
c1_replay_version(struct c1 *c1, char *omf)
{
    struct c1_version vers;

    merr_t err;

    err = omf_c1_ver_unpack(omf, &vers);
    if (ev(err))
        return err;

    if (vers.c1v_version > C1_VERSION) {
        hse_log(
            HSE_ERR "%s Reading new OMF (version %u) with old "
                    "binary (version %d), please upgrade.",
            __func__,
            vers.c1v_version,
            C1_VERSION);
        return merr(ev(EPROTO));
    }

    if (vers.c1v_magic != C1_MAGIC) {
        hse_log(HSE_ERR "%s Invalid magic 0x%x", __func__, (unsigned int)vers.c1v_magic);
        return merr(ev(EINVAL));
    }

    c1->c1_version = vers.c1v_version;

    return 0;
}

merr_t
c1_replay_add_info(struct c1 *c1, char *omf)
{
    struct c1_info *   newinfo;
    struct c1_journal *jrnl;

    merr_t err;

    jrnl = c1->c1_jrnl;

    newinfo = malloc(sizeof(*newinfo));
    if (!newinfo)
        return merr(ev(ENOMEM));

    INIT_LIST_HEAD(&newinfo->c1i_list);

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)newinfo);
    if (ev(err)) {
        free(newinfo);
        return err;
    }

    list_add_tail(&newinfo->c1i_list, &c1->c1_rep.c1r_info);

    jrnl->c1j_capacity = newinfo->c1i_capacity;
    jrnl->c1j_dtime = newinfo->c1i_dtime;
    jrnl->c1j_dsize = newinfo->c1i_dsize;

    hse_log(
        HSE_DEBUG "c1 ADD INFO  seqno %ld c1i_gen %ld "
                  "c1i_dtime %ld c1i_dsize %ld "
                  "c1i_capacity %ld",
        (unsigned long)newinfo->c1i_seqno,
        (unsigned long)newinfo->c1i_gen,
        (unsigned long)newinfo->c1i_dtime,
        (unsigned long)newinfo->c1i_dsize,
        (unsigned long)newinfo->c1i_capacity);

    return 0;
}

merr_t
c1_replay_add_desc(struct c1 *c1, char *omf)
{
    struct c1_desc *newdesc;

    merr_t err;

    newdesc = malloc(sizeof(*newdesc));
    if (!newdesc)
        return merr(ev(ENOMEM));

    INIT_LIST_HEAD(&newdesc->c1d_list);

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)newdesc);
    if (ev(err)) {
        free(newdesc);
        return err;
    }

    list_add_tail(&newdesc->c1d_list, &c1->c1_rep.c1r_desc);

    hse_log(
        HSE_DEBUG "c1 ADD DESC oid %ld ver %ld-%ld state %d",
        (unsigned long)newdesc->c1d_oid,
        (unsigned long)newdesc->c1d_seqno,
        (unsigned long)newdesc->c1d_gen,
        (unsigned int)newdesc->c1d_state);

    return 0;
}

merr_t
c1_replay_add_ingest(struct c1 *c1, char *omf)
{
    /* Obsolete record. Ignore if it is found. */
    return 0;
}

merr_t
c1_replay_add_reset(struct c1 *c1, char *omf)
{
    struct c1_reset *reset;

    merr_t err;

    reset = malloc(sizeof(*reset));
    if (!reset)
        return merr(ev(ENOMEM));

    INIT_LIST_HEAD(&reset->c1reset_list);

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)reset);
    if (ev(err)) {
        free(reset);
        return err;
    }

    list_add_tail(&reset->c1reset_list, &c1->c1_rep.c1r_reset);

    hse_log(
        HSE_DEBUG "c1 ADD Reset old ver %ld-%ld new vers %ld-%ld",
        (unsigned long)reset->c1reset_seqno,
        (unsigned long)reset->c1reset_gen,
        (unsigned long)reset->c1reset_newseqno,
        (unsigned long)reset->c1reset_newgen);

    return 0;
}

merr_t
c1_replay_add_complete(struct c1 *c1, char *omf)
{
    struct c1_complete *cmp;

    merr_t err;

    cmp = malloc(sizeof(*cmp));
    if (!cmp)
        return merr(ev(ENOMEM));

    INIT_LIST_HEAD(&cmp->c1c_list);

    err = c1_record_unpack(omf, c1->c1_version, (union c1_record *)cmp);
    if (ev(err)) {
        free(cmp);
        return err;
    }

    list_add_tail(&cmp->c1c_list, &c1->c1_rep.c1r_complete);

    return 0;
}

void
c1_replay_add_close(struct c1 *c1, char *omf)
{
    c1->c1_rep.c1r_close = true;
}

static merr_t
c1_replay_alloc_tree(
    struct c1 *       c1,
    struct mpool *    mp,
    u64               oid1,
    u64               oid2,
    struct c1_info *  info,
    struct list_head *desclist,
    int               count)
{
    struct c1_log_desc *descp;
    struct c1_desc *    desc, *desc_tmp;
    merr_t              err;
    u64                 seqno;
    u32                 gen;
    struct c1_tree *    tree;
    int                 i;

    descp = malloc_array(count, sizeof(*descp));
    if (!descp)
        return merr(ev(ENOMEM));

    memset(descp, 0, sizeof(*descp) * count);
    i = 0;
    gen = 0;
    seqno = 0;

    list_for_each_entry_safe (desc, desc_tmp, desclist, c1d_list) {
        list_del(&desc->c1d_list);

        descp[i].c1_oid = desc->c1d_oid;
        seqno = desc->c1d_seqno;
        gen = desc->c1d_gen;
        free(desc);

        assert(i < count);
        i++;
    }

    if (i == 0) {
        free(descp);
        return merr(ev(EINVAL));
    }

    err = c1_tree_create(
        mp, seqno, gen, descp, oid1, oid2, MP_MED_STAGING, 0, count, info->c1i_capacity, &tree);
    if (ev(err))
        return err;

    list_add_tail(&tree->c1t_list, &c1->c1_tree_inuse);

    atomic_inc(&c1->c1_jrnl->c1j_treecnt);

    return 0;
}

merr_t
c1_replay_build_trees(struct mpool *mp, u64 oid1, u64 oid2, struct c1 *c1)
{
    struct c1_desc * desc, *desc_tmp, *first;
    struct c1_info * info;
    struct list_head desclist;
    merr_t           err;
    int              count;

    if (list_empty(&c1->c1_rep.c1r_info))
        return 0;

    info = list_first_entry_or_null(&c1->c1_rep.c1r_info, typeof(*info), c1i_list);
    assert(info);

    list_del(&info->c1i_list);

    while (!list_empty(&c1->c1_rep.c1r_desc)) {
        first = list_first_entry_or_null(&c1->c1_rep.c1r_desc, typeof(*desc), c1d_list);
        assert(first);

        INIT_LIST_HEAD(&desclist);
        count = 1;
        list_del(&first->c1d_list);
        list_add_tail(&first->c1d_list, &desclist);

        list_for_each_entry_safe (desc, desc_tmp, &c1->c1_rep.c1r_desc, c1d_list) {
            if ((first->c1d_seqno == desc->c1d_seqno) && (first->c1d_gen == desc->c1d_gen)) {
                list_del(&desc->c1d_list);
                list_add_tail(&desc->c1d_list, &desclist);
                count++;
            }
        }

        if (count != HSE_C1_DEFAULT_STRIPE_WIDTH)
            hse_log(
                HSE_ERR "c1 metadata error, no. of logs "
                        "%d do not match with stripe width %d",
                count,
                HSE_C1_DEFAULT_STRIPE_WIDTH);

        err = c1_replay_alloc_tree(c1, mp, oid1, oid2, info, &desclist, count);
        if (ev(err))
            break;
    }

    free(info);

    return 0;
}

merr_t
c1_replay_remove_reset_trees(struct mpool *mp, struct c1 *c1)
{
    struct c1_tree * tree, *tree_tmp;
    struct c1_reset *reset, *tmp_reset;

    list_for_each_entry_safe (reset, tmp_reset, &c1->c1_rep.c1r_reset, c1reset_list) {

        list_for_each_entry_safe (tree, tree_tmp, &c1->c1_tree_inuse, c1t_list) {

            if ((reset->c1reset_seqno == tree->c1t_seqno) &&
                (reset->c1reset_gen == tree->c1t_gen)) {

                hse_log(
                    HSE_DEBUG "c1 Reset tree %p "
                              "old ver %ld-%ld new ver %ld-%ld",
                    tree,
                    (unsigned long)tree->c1t_seqno,
                    (unsigned long)tree->c1t_gen,
                    (unsigned long)reset->c1reset_newseqno,
                    (unsigned long)reset->c1reset_newgen);

                tree->c1t_seqno = reset->c1reset_newseqno;
                tree->c1t_gen = reset->c1reset_newgen;
            }
        }

        list_del(&reset->c1reset_list);
        free(reset);
    }

    return 0;
}

void
c1_replay_sort_trees(struct c1 *c1)
{
    struct list_head list;
    struct c1_tree * tree, *tree_tmp;
    struct c1_tree * first, *next;

    if (list_empty(&c1->c1_tree_inuse))
        return;

    INIT_LIST_HEAD(&list);

    while (!list_empty(&c1->c1_tree_inuse)) {
        first = list_first_entry_or_null(&c1->c1_tree_inuse, typeof(*first), c1t_list);
        assert(first);

        list_del(&first->c1t_list);
        next = first;
        list_for_each_entry_safe (tree, tree_tmp, &c1->c1_tree_inuse, c1t_list) {
            if (tree->c1t_seqno < next->c1t_seqno)
                next = tree;
        }

        if (first != next) {
            list_add(&first->c1t_list, &c1->c1_tree_inuse);
            list_del(&next->c1t_list);
        }

        list_add_tail(&next->c1t_list, &list);
    }

    if (!list_empty(&list)) {
        assert(list_empty(&c1->c1_tree_inuse));
        list_splice_tail(&list, &c1->c1_tree_inuse);
    }

    next = list_last_entry(&c1->c1_tree_inuse, typeof(*next), c1t_list);

    hse_log(
        HSE_DEBUG "c1 replay setting current ver to %ld=%ld",
        (unsigned long)next->c1t_seqno,
        (unsigned long)next->c1t_gen);

    /*
     * Update the c1 version by setting it to that of the latest
     * tree.
     */
    c1_journal_set_seqno(c1->c1_jrnl, next->c1t_seqno, next->c1t_gen);
}

static merr_t
c1_replay_trees(struct mpool *mp, u64 oid1, u64 oid2, struct c1 *c1)
{
    struct c1_tree *tree, *tree_tmp;
    merr_t          err;

    err = c1_replay_build_trees(mp, oid1, oid2, c1);
    if (ev(err))
        return err;

    err = c1_replay_remove_reset_trees(mp, c1);
    if (ev(err))
        return err;

    c1_replay_sort_trees(c1);

    mutex_lock(&c1->c1_active_mtx);
    list_for_each_entry_safe (tree, tree_tmp, &c1->c1_tree_inuse, c1t_list) {

        err = c1_tree_open(tree, true);
        if (ev(err)) {
            hse_elog(HSE_ERR "%s: Open failed: @@e", err, __func__);
            break;
        }

        err = c1_tree_replay(c1, tree);
        if (ev(err))
            break;

        list_del(&tree->c1t_list);
        list_add_tail(&tree->c1t_list, &c1->c1_tree_clean);
    }

    assert(err || list_empty(&c1->c1_tree_inuse));

    mutex_unlock(&c1->c1_active_mtx);

    if (!err && c1_ikvdb(c1))
        ikvdb_c1_set_seqno(c1_ikvdb(c1), c1_get_kvdb_seqno(c1));

    return err;
}

static void
c1_replay_trees_reset(struct c1 *c1)
{
    struct c1_tree *tree;

    mutex_lock(&c1->c1_active_mtx);
    list_for_each_entry (tree, &c1->c1_tree_clean, c1t_list)
        c1_tree_reset(tree, tree->c1t_seqno, tree->c1t_gen);
    mutex_unlock(&c1->c1_active_mtx);
}

static merr_t
c1_replay_process_ingest(struct c1 *c1)
{
    struct c1_ingest *ingest;
    u64               kvseqno;

    kvseqno = C1_INVALID_SEQNO;

    list_for_each_entry (ingest, &c1->c1_rep.c1r_ingest, c1ing_list)
        if (kvseqno < ingest->c1ing_seqno)
            kvseqno = ingest->c1ing_seqno;

    c1->c1_ingest_kvseqno = kvseqno;

    return 0;
}

static void
c1_replay_close(struct c1 *c1)
{
    struct c1_complete *cmp, *cmp_tmp;
    struct c1_desc *    desc, *desc_tmp;
    struct c1_info *    info, *info_tmp;
    struct c1_reset *   reset, *reset_tmp;
    struct c1_ingest *  ingest, *ingest_tmp;

    list_for_each_entry_safe (desc, desc_tmp, &c1->c1_rep.c1r_desc, c1d_list) {
        list_del(&desc->c1d_list);
        free(desc);
    }

    list_for_each_entry_safe (cmp, cmp_tmp, &c1->c1_rep.c1r_complete, c1c_list) {
        list_del(&cmp->c1c_list);
        free(cmp);
    }

    list_for_each_entry_safe (info, info_tmp, &c1->c1_rep.c1r_info, c1i_list) {
        list_del(&info->c1i_list);
        free(info);
    }

    list_for_each_entry_safe (reset, reset_tmp, &c1->c1_rep.c1r_reset, c1reset_list) {
        list_del(&reset->c1reset_list);
        free(reset);
    }

    list_for_each_entry_safe (ingest, ingest_tmp, &c1->c1_rep.c1r_ingest, c1ing_list) {
        list_del(&ingest->c1ing_list);
        free(ingest);
    }
}

merr_t
c1_replay_impl(struct c1 *c1)
{
    merr_t             err;
    merr_t             err2;
    bool               clean;
    struct c1_journal *jrnl;
    struct ikvdb *     ikvdb;

    jrnl = c1->c1_jrnl;
    assert(jrnl != NULL);

    clean = c1_is_clean(c1);
    ikvdb = c1_ikvdb(c1);

    if (!clean) {
        err = ikvdb_c1_replay_open(ikvdb, &c1->c1_replay_hdl);
        if (ev(err))
            return err;

        ikvdb_set_replaying(ikvdb);

        /* Flush the active kvms so that the new one will be
         * sufficiently provisioned by c0sk_ingest_tune() to
         * prevent seqno ordering problems.
         */
        ikvdb_flush(ikvdb);
    }

    err = c1_replay_trees(jrnl->c1j_mp, jrnl->c1j_oid1, jrnl->c1j_oid2, c1);
    if (ev(err))
        hse_elog(HSE_ERR "%s: c1 tree replay failed: @@e", err, __func__);

    if (!clean) {
        ikvdb_unset_replaying(ikvdb);

        err2 = ikvdb_c1_replay_close(ikvdb, c1->c1_replay_hdl);

        c1->c1_replay_hdl = 0;
        if (ev(err2) && !err)
            err = err2;

        /* Erase c1 logs to make subsequent replays to finish qucikly
         * without requiring to go through their contents.
         */
        if (!err)
            c1_replay_trees_reset(c1);
    }

    c1_replay_close(c1);

    return err;
}

merr_t
c1_replay(struct c1 *c1)
{
    merr_t err;

    assert(c1->c1_jrnl);

    err = c1_journal_replay(c1, c1->c1_jrnl, c1_journal_replay_default_cb);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 journal replay failed: @@e", err, __func__);
        c1_replay_close(c1);
        return err;
    }

    err = c1_replay_process_ingest(c1);
    if (ev(err))
        hse_elog(HSE_ERR "%s: c1 process ingest failed: @@e", err, __func__);

    if (c1_rdonly(c1)) {
        c1_replay_close(c1);
        return err;
    }

    return c1_replay_impl(c1);
}

merr_t
c1_new_tree(
    struct c1_journal *jrnl,
    u32                stripsize,
    u32                stripewidth,
    struct perfc_set * pcset,
    struct c1_tree **  out)
{
    struct c1_log_desc *desc;
    struct c1_tree *    tree;
    int                 numdesc;
    int                 i;
    merr_t              err;
    merr_t              err2;

    err = c1_tree_alloc(
        jrnl->c1j_mp,
        jrnl->c1j_seqno,
        jrnl->c1j_gen,
        jrnl->c1j_oid1,
        jrnl->c1j_oid2,
        &jrnl->c1j_mediaclass,
        stripsize,
        stripewidth,
        jrnl->c1j_capacity,
        &tree);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 tree alloc failed: @@e", err, __func__);
        return err;
    }

    err = c1_tree_get_desc(tree, &desc, &numdesc);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: cannot get log descriptors : @@e", err, __func__);
        goto err_exit2;
    }

    for (i = 0; i < numdesc; i++) {
        err = c1_journal_write_desc(jrnl, C1_DESC_INIT, desc[i].c1_oid, jrnl->c1j_seqno, 0);
        if (ev(err)) {
            hse_elog(HSE_ERR "%s: journal write failed : @@e", err, __func__);
            goto err_exit;
        }
    }

    err = c1_tree_make(tree);
    if (ev(err))
        goto err_exit;

    if (out)
        *out = tree;
    else
        c1_tree_close(tree);

    if (pcset) {
        perfc_inc(pcset, PERFC_BA_C1_TALLOC);
        perfc_inc(pcset, PERFC_BA_C1_TACTIVE);
    }

    atomic_inc(&jrnl->c1j_treecnt);

    return c1_journal_flush(jrnl);

err_exit:
    err2 = c1_tree_destroy(jrnl->c1j_mp, desc, numdesc);
    if (ev(err2))
        hse_elog(HSE_ERR "%s: c1 tree destroy failed: @@e", err2, __func__);
err_exit2:
    c1_tree_close(tree);
    return err;
}

merr_t
c1_destroy_tree(struct mpool *mp, u64 oid1, u64 oid2, struct c1 *c1)
{
    struct c1_tree *    tree, *tree_tmp;
    struct c1_log_desc *desc;
    int                 numdesc;
    merr_t              err, err2;

    err = c1_replay_build_trees(mp, oid1, oid2, c1);
    if (ev(err))
        return err;

    list_for_each_entry_safe (tree, tree_tmp, &c1->c1_tree_inuse, c1t_list) {
        list_del(&tree->c1t_list);

        err2 = ev(c1_tree_get_desc(tree, &desc, &numdesc));
        assert(err2 == 0);

        err2 = c1_tree_destroy(mp, desc, numdesc);
        if (ev(err2 != 0))
            err = err2;

        free(desc);
        free_aligned(tree);
    }

    return err;
}

static merr_t
c1_reset_tree(struct c1 *c1, struct c1_tree *tree, u64 newseqno, u32 newgen)
{
    merr_t err;

    if (c1_jrnl_reaching_capacity(c1)) {
        err = c1_compact(c1);
        if (ev(err))
            return err;
    }

    hse_log(
        HSE_DEBUG "c1 Resetting tree ver %ld-%ld new ver %ld-%ld",
        (unsigned long)tree->c1t_seqno,
        (unsigned long)tree->c1t_gen,
        (unsigned long)newseqno,
        (unsigned long)newgen);

    err = c1_journal_reset_tree(c1->c1_jrnl, tree->c1t_seqno, tree->c1t_gen, newseqno, newgen);
    if (ev(err))
        return err;

    err = c1_tree_reset(tree, newseqno, newgen);
    if (ev(err))
        return err;

    return 0;
}

static merr_t
c1_close_trees_impl(struct c1 *c1, struct list_head *head)
{
    struct c1_tree *tree, *tree_tmp;
    merr_t          err = 0;
    merr_t          err2;

    list_for_each_entry_safe (tree, tree_tmp, head, c1t_list) {
        list_del(&tree->c1t_list);
        err2 = c1_tree_close(tree);
        if (err2 != 0)
            err = err2;
    }

    return err;
}

merr_t
c1_close_trees(struct c1 *c1)
{
    merr_t err, err2, err3;

    err = c1_close_trees_impl(c1, &c1->c1_tree_reset);
    if (ev(err))
        hse_elog(HSE_ERR "%s: c1 close of reset tree failed: @@e", err, __func__);

    err2 = c1_close_trees_impl(c1, &c1->c1_tree_clean);
    if (ev(err2))
        hse_elog(HSE_ERR "%s: c1 close of clean tree failed: @@e", err2, __func__);

    err3 = c1_close_trees_impl(c1, &c1->c1_tree_inuse);
    if (ev(err3))
        hse_elog(HSE_ERR "%s: c1 close of inuse tree failed: @@e", err3, __func__);
    if (ev(err))
        return err;

    if (ev(err2))
        return err2;

    return err3;
}

struct c1_tree *
c1_current_tree(struct c1 *c1)
{
    struct c1_tree *tree;

    assert(!list_empty(&c1->c1_tree_inuse));

    mutex_lock(&c1->c1_active_mtx);
    tree = list_last_entry(&c1->c1_tree_inuse, struct c1_tree, c1t_list);
    mutex_unlock(&c1->c1_active_mtx);

    assert(tree != NULL);

    return tree;
}

static struct c1_tree *
c1_next_tree_from_list(struct c1 *c1, struct list_head *head, u64 newseqno, u32 newgen)
{
    struct c1_tree *tree;
    merr_t          err;

    if (list_empty(head))
        return NULL;

    tree = list_first_entry_or_null(head, typeof(*tree), c1t_list);
    assert(tree != NULL);

    err = c1_reset_tree(c1, tree, newseqno, newgen);
    if (ev(err))
        return NULL;

    list_del(&tree->c1t_list);
    c1_cache_add(c1, tree);

    return tree;
}

static merr_t
c1_next_tree_impl(struct c1 *c1)
{
    struct c1_tree *   tree;
    struct c1_journal *jrnl;
    merr_t             err;

    mutex_lock(&c1->c1_active_mtx);

    jrnl = c1->c1_jrnl;
    c1_journal_inc_seqno(jrnl);

    tree = c1_next_tree_from_list(c1, &c1->c1_tree_clean, jrnl->c1j_seqno, jrnl->c1j_gen);
    mutex_unlock(&c1->c1_active_mtx);

    if (tree != NULL) {
        hse_log(
            HSE_DEBUG "c1 got tree %p ver %ld-%ld from cleanlist",
            tree,
            (unsigned long)tree->c1t_seqno,
            (unsigned long)tree->c1t_gen);
        perfc_inc(&c1->c1_pcset_tree, PERFC_BA_C1_TREUSE);
        perfc_inc(&c1->c1_pcset_tree, PERFC_BA_C1_TACTIVE);

        return 0;
    }

    if (c1_jrnl_reaching_capacity(c1)) {
        err = c1_compact(c1);
        if (ev(err))
            return err;
    }

    if (atomic_read(&jrnl->c1j_treecnt) >= HSE_C1_TREE_CNT_UB) {
	    hse_log(HSE_ERR "No. of c1 trees cannot exceed %d", HSE_C1_TREE_CNT_UB);
	    return merr(ENOSPC);
    }

    err = c1_new_tree(
        jrnl, HSE_C1_DEFAULT_STRIP_SIZE, HSE_C1_DEFAULT_STRIPE_WIDTH, &c1->c1_pcset_tree, &tree);
    if (ev(err))
        return err;

    c1_cache_add(c1, tree);

    return c1_tree_open(tree, false);
}

merr_t
c1_next_tree(struct c1 *c1)
{
    merr_t err;
    bool   next;

    if (c1_cache_remove(c1))
        return 0;

    mutex_lock(&c1->c1_alloc_mtx);
    err = c1_next_tree_impl(c1);
    mutex_unlock(&c1->c1_alloc_mtx);

    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 tree allocation failed: @@e", err, __func__);
        return err;
    }

    next = c1_cache_remove(c1);
    if (!next)
        return merr(ev(ENOMEM));

    return 0;
}

merr_t
c1_mark_tree_complete(struct c1 *c1, struct c1_tree *tree)
{
    struct c1_complete cmp;
    merr_t             err;

    err = c1_tree_get_complete(tree, &cmp);
    if (ev(err))
        return err;

    if (c1_jrnl_reaching_capacity(c1)) {
        err = c1_compact(c1);
        if (ev(err))
            return err;
    }

    return c1_journal_complete_tree(c1->c1_jrnl, cmp.c1c_seqno, cmp.c1c_gen, cmp.c1c_kvseqno);
}

merr_t
c1_invalidate_tree(struct c1 *c1, u64 seqno, merr_t status, u64 cnid, const struct kvs_ktuple *kt)
{
    struct c1_tree *   tree, *tree_tmp;
    struct c1_complete cmp;
    merr_t             err;

    err = 0;

    mutex_lock(&c1->c1_active_mtx);
    list_for_each_entry_safe (tree, tree_tmp, &c1->c1_tree_inuse, c1t_list) {

        /*
         * Do not invalidate the last or only tree in the inuse list
         * that may not be exhausted.
         */
        if (atomic_read(&c1->c1_active_cnt) == 1)
            break;

        err = c1_tree_get_complete(tree, &cmp);
        if (ev(err)) {
            hse_elog(HSE_ERR "%s: c1 get tree failed: @@e", err, __func__);
            assert(err == 0);
            break;
        }

        if (cmp.c1c_kvseqno >= seqno)
            break;

        hse_log(
            HSE_DEBUG "c1 invalidating tree %p ver %ld-%ld "
                      "with seqno %ld cur. seqno %ld",
            tree,
            (unsigned long)tree->c1t_seqno,
            (unsigned long)tree->c1t_gen,
            (unsigned long)cmp.c1c_kvseqno,
            (unsigned long)seqno);

        atomic_dec(&c1->c1_active_cnt);
        list_del(&tree->c1t_list);
        list_add_tail(&tree->c1t_list, &c1->c1_tree_clean);
        perfc_inc(&c1->c1_pcset_tree, PERFC_BA_C1_TINVAL);
        perfc_dec(&c1->c1_pcset_tree, PERFC_BA_C1_TACTIVE);
    }

    mutex_unlock(&c1->c1_active_mtx);

    return err;
}

u64
c1_get_time(u64 time)
{
    if (time == 0)
        time = HSE_C1_DEFAULT_DTIME;

    if ((time < HSE_C1_MIN_DTIME) || (time > HSE_C1_MAX_DTIME)) {
        u64 newtime;

        newtime = clamp_t(u64, time, HSE_C1_MIN_DTIME, HSE_C1_MAX_DTIME);

        hse_log(
            HSE_INFO "Invalid durability time %lu ms, "
                     "setting to %lu ms",
            (ulong)time,
            (ulong)newtime);

        time = newtime;
    }

    return time;
}

merr_t
c1_parse_cparams(struct kvdb_cparams *cparams, u64 *capacity, u64 *ntrees)
{
    if (!cparams)
        return merr(ev(EINVAL));

    *capacity = c1_get_capacity(cparams->dur_capacity * MB);
    *ntrees = 0;

    return 0;
}
