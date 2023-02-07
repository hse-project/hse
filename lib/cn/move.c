/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <hse/util/list.h>
#include <hse/util/rmlock.h>

#include <hse/error/merr.h>
#include <hse/logging/logging.h>

#include <hse/ikvdb/cndb.h>
#include <hse/ikvdb/kvset_view.h>
#include <hse/ikvdb/cn.h>

#include "cn_tree_compact.h"
#include "cn_tree_internal.h"
#include "cn_tree.h"
#include "kvset.h"
#include "route.h"

merr_t
cn_move(
    struct cn_compaction_work *w,
    struct cn_tree_node       *src_node,
    struct kvset_list_entry   *src_list,
    uint32_t                   src_cnt,
    bool                       src_del,
    struct cn_tree_node       *tgt_node)
{
    struct kvset_list_entry *src, *tgt;
    struct list_head *src_head, *tgt_head;
    struct cn_tree *tree;
    uint64_t src_nodeid;

    INVARIANT(w && src_node && tgt_node);
    INVARIANT(!src_cnt == !src_list);

    tree = w->cw_tree;
    src_head = &src_node->tn_kvset_list;
    tgt_head = &tgt_node->tn_kvset_list;

    src = src_list;
    if (src) {
        uint64_t *src_ksidv;
        merr_t err;
        void *lock;

        src_ksidv = malloc(sizeof(*src_ksidv) * src_cnt);
        if (!src_ksidv)
            return merr(ENOMEM);

        /* Must hold the tree lock while iterating over the kvset list
         * (because if src_node is the cn root node it could change).
         */
        rmlock_rlock(&tree->ct_lock, &lock);
        for (uint32_t i = 0; i < src_cnt; i++) {
            assert(src);
            assert(kvset_get_work(src->le_kvset) == w);

            src_ksidv[i] = kvset_get_id(src->le_kvset);
            src = list_next_entry_or_null(src, le_link, src_head);
        }

        assert(!src_del || !src);
        rmlock_runlock(lock);

        err = cndb_record_kvsetv_move(cn_get_cndb(tree->cn), tree->cnid, src_node->tn_nodeid,
                                      tgt_node->tn_nodeid, src_cnt, src_ksidv);

        free(src_ksidv);

        if (err)
            return err;
    }

    /* The cn_move operation has been committed to cNDB.
     * There must be no failures beyond this point.
     */
    src_nodeid = src_node->tn_nodeid;
    src = src_list;

    rmlock_wlock(&tree->ct_lock);
    tgt = list_first_entry_or_null(tgt_head, typeof(*tgt), le_link);

    while (src_cnt > 0) {
        if (!tgt || kvset_younger(src->le_kvset, tgt->le_kvset)) {
            struct kvset_list_entry *src_next, *tgt_prev;
            uint32_t compc = kvset_get_compc(src->le_kvset), pcompc;

            src_next = list_next_entry_or_null(src, le_link, src_head);
            list_del_init(&src->le_link);

            if (tgt) {
                tgt_prev = list_prev_entry_or_null(tgt, le_link, tgt_head);
                pcompc = tgt_prev ? kvset_get_compc(tgt_prev->le_kvset) : 0;
                compc = clamp_t(uint, compc, pcompc, kvset_get_compc(tgt->le_kvset));

                kvset_list_add_tail(src->le_kvset, &tgt->le_link);
            } else {
                tgt_prev = list_last_entry_or_null(tgt_head, typeof(*tgt_prev), le_link);
                pcompc = tgt_prev ? kvset_get_compc(tgt_prev->le_kvset) : 0;
                compc = clamp_t(uint, compc, pcompc, UINT32_MAX);

                kvset_list_add_tail(src->le_kvset, tgt_head);
            }

            kvset_set_compc(src->le_kvset, compc);

            src = src_next;
            src_cnt--;
        } else {
            tgt = list_next_entry_or_null(tgt, le_link, tgt_head);
        }
    }

    if (src_del) {
        assert(list_empty(src_head));
        route_map_delete(tree->ct_route_map, src_node->tn_route_node);
        src_node->tn_route_node = NULL;
    }

    cn_tree_samp(tree, &w->cw_samp_pre);
    cn_tree_samp_update_move(w, src_node);
    cn_tree_samp_update_move(w, tgt_node);
    cn_tree_samp(tree, &w->cw_samp_post);

    /* Unmark input kvsets */
    {
        struct kvset_list_entry *le;

        list_for_each_entry(le, &tgt_node->tn_kvset_list, le_link) {
            bool from_src = kvset_get_nodeid(le->le_kvset) == src_nodeid;

            /* If source node was deleted, update all kvsets in tgt, otherwise only update the
             * kvsets that were moved from src.
             */
            if (src_del || from_src) {
                assert(kvset_get_work(le->le_kvset) == w);
                kvset_set_work(le->le_kvset, NULL);

                kvset_set_rule(le->le_kvset, w->cw_rule);
                kvset_set_nodeid(le->le_kvset, tgt_node->tn_nodeid);
            }
        }
    }

    rmlock_wunlock(&tree->ct_lock);

    return 0;
}

merr_t
cn_join(struct cn_compaction_work *w)
{
    struct cn_tree_node *src_node, *tgt_node;
    struct kvset_list_entry *src_list, *le;
    uint32_t src_cnt, tgt_cnt;
    bool src_del = true;
    merr_t err;

    src_node = w->cw_join;
    tgt_node = w->cw_node;

    assert(src_node);
    assert(cn_node_isleaf(src_node) && cn_node_isleaf(tgt_node));

    src_list = list_first_entry_or_null(&src_node->tn_kvset_list, typeof(*src_list), le_link);
    src_cnt = cn_ns_kvsets(&src_node->tn_ns);
    tgt_cnt = cn_ns_kvsets(&tgt_node->tn_ns);
    assert(tgt_cnt == w->cw_kvset_cnt);

    err = cn_move(w, src_node, src_list, src_cnt, src_del, tgt_node);
    if (!err) {
        assert(cn_ns_kvsets(&tgt_node->tn_ns) == src_cnt + tgt_cnt);
        log_debug("src %lu (%u) -> tgt %lu (%u)",
                  src_node->tn_nodeid, src_cnt, tgt_node->tn_nodeid, tgt_cnt);
    }

    if (err) {
        list_for_each_entry(le, &src_node->tn_kvset_list, le_link) {
            assert(kvset_get_work(le->le_kvset) == w);
            kvset_set_work(le->le_kvset, NULL);
        }
    }

    return err;
}
