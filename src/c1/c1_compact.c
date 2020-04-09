/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_private.h"

merr_t
c1_compact(struct c1 *c1)
{
    struct c1_journal *jrnl;

    merr_t err;
    u64    start;

    jrnl = c1->c1_jrnl;

    start = perfc_lat_start(&jrnl->c1j_pcset);

    err = c1_journal_compact_begin(jrnl);
    if (ev(err))
        return err;

    err = c1_journal_format(jrnl);
    if (ev(err))
        return err;

    err = c1_compact_reset_trees(c1);
    if (ev(err))
        return err;

    err = c1_compact_clean_trees(c1);
    if (ev(err))
        return err;

    err = c1_compact_inuse_trees(c1);
    if (ev(err))
        return err;

    err = c1_compact_new_trees(c1);
    if (ev(err))
        return err;

    err = c1_journal_compact_end(jrnl);
    if (ev(err))
        return err;

    if (PERFC_ISON(&jrnl->c1j_pcset)) {
        perfc_inc(&jrnl->c1j_pcset, PERFC_BA_C1_JRNLC);
        perfc_rec_lat(&jrnl->c1j_pcset, PERFC_LT_C1_JRNLC, start);
    }

    return 0;
}

BullseyeCoverageSaveOff static merr_t
c1_compact_add_tree(struct c1_journal *jrnl, struct c1_tree *tree, int status)
{
    struct c1_log_desc *desc;
    int                 numdesc;
    int                 i;
    merr_t              err;

    err = c1_tree_get_desc(tree, &desc, &numdesc);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: cannot get log descriptors : @@e", err, __func__);
        return err;
    }

    for (i = 0; i < numdesc; i++) {
        err = c1_journal_write_desc(jrnl, status, desc[i].c1_oid, tree->c1t_seqno, tree->c1t_gen);
        if (ev(err)) {
            hse_elog(HSE_ERR "%s: journal write failed : @@e", err, __func__);
            return err;
        }
    }

    return 0;
}
BullseyeCoverageRestore

    static merr_t
    c1_compact_add_trees(struct c1_journal *jrnl, struct list_head *head, int status)
{
    struct c1_tree *tree;
    merr_t          err;

    list_for_each_entry (tree, head, c1t_list) {
        err = c1_compact_add_tree(jrnl, tree, status);
        if (ev(err))
            return err;
    }

    return 0;
}

#undef c1_compact_new_trees
merr_t
c1_compact_new_trees(struct c1 *c1)
{
    return c1_compact_add_trees(c1->c1_jrnl, &c1->c1_tree_new, C1_DESC_INIT);
}

#undef c1_compact_inuse_trees
merr_t
c1_compact_inuse_trees(struct c1 *c1)
{
    return c1_compact_add_trees(c1->c1_jrnl, &c1->c1_tree_inuse, C1_DESC_CLEAN);
}

#undef c1_compact_reset_trees
merr_t
c1_compact_reset_trees(struct c1 *c1)
{
    return c1_compact_add_trees(c1->c1_jrnl, &c1->c1_tree_reset, C1_DESC_CLEAN);
}

#undef c1_compact_clean_trees
merr_t
c1_compact_clean_trees(struct c1 *c1)
{
    return c1_compact_add_trees(c1->c1_jrnl, &c1->c1_tree_clean, C1_DESC_CLEAN);
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_tree_ut_impl.i"
#include "c1_compact_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
