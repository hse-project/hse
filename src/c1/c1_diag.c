/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_private.h"

BullseyeCoverageSaveOff merr_t
c1_diag_replay_journal(struct c1 *c1, c1_journal_replay_cb *cb)
{
    merr_t err;

    err = c1_journal_replay(c1, c1->c1_jrnl, cb);
    if (ev(err))
        return err;

    return 0;
}

static merr_t
c1_diag_tree_replay(struct c1 *c1, struct c1_tree *tree, c1_journal_replay_cb *cb)
{
    int    numlogs;
    merr_t err = 0;
    merr_t err2;
    int    i;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    for (i = 0; i < numlogs; i++) {
        err2 = c1_log_diag_replay(tree->c1t_log[i], cb, c1, c1->c1_version);
        if (ev(err2)) {
            err = err2;
            continue;
        }
    }

    return err;
}

merr_t
c1_diag_replay_trees(struct c1 *c1, c1_journal_replay_cb *cb)
{
    struct c1_tree *   tree, *tree_tmp;
    merr_t             err;
    struct c1_journal *jrnl;
    u64                oid1, oid2;
    struct mpool *     ds;

    jrnl = c1->c1_jrnl;
    assert(jrnl != NULL);

    oid1 = jrnl->c1j_oid1;
    oid2 = jrnl->c1j_oid2;
    ds = jrnl->c1j_ds;

    err = c1_replay_build_trees(ds, oid1, oid2, c1);
    if (ev(err))
        return err;

    err = c1_replay_remove_reset_trees(ds, c1);
    if (ev(err))
        return err;

    mutex_lock(&c1->c1_active_mtx);
    list_for_each_entry_safe (tree, tree_tmp, &c1->c1_tree_inuse, c1t_list) {

        err = c1_tree_open(tree, true);
        if (ev(err)) {
            hse_elog(HSE_ERR "%s: Open failed: @@e", err, __func__);
            break;
        }

        err = c1_diag_tree_replay(c1, tree, cb);
        if (ev(err))
            break;

        list_del(&tree->c1t_list);

        list_del(&tree->c1t_list);
        list_add_tail(&tree->c1t_list, &c1->c1_tree_clean);
    }

    assert(err || list_empty(&c1->c1_tree_inuse));

    mutex_unlock(&c1->c1_active_mtx);

    return err;
}
BullseyeCoverageRestore
