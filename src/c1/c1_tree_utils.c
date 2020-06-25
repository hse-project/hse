/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/cndb.h>

#include "c1_omf_internal.h"

static void
c1_tree_keycount(struct c1_tree *tree, u64 *ingestcount, u64 *replaycount)
{
    int i;
    int numlogs;
    u64 ingest;
    u64 replay;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    *ingestcount = 0;
    *replaycount = 0;

    if (!tree->c1t_log || (numlogs <= 0))
        return;

    for (i = 0; i < numlogs; i++) {
        c1_log_keycount(tree->c1t_log[i], &ingest, &replay);
        *ingestcount += ingest;
        *replaycount += replay;
    }
}

BullseyeCoverageSaveOff static void *
c1_tree_txn_next(struct list_head *list)
{
    struct c1_treetxn *next;

    next = list_first_entry_or_null(list, typeof(*next), c1txn_list);

    return next;
}

static int
c1_tree_txn_cmp(void *arg1, void *arg2)
{
    struct c1_treetxn *t1 = arg1;
    struct c1_treetxn *t2 = arg2;

    if (t1->c1txn_id > t2->c1txn_id)
        return 1;

    if (t1->c1txn_id < t2->c1txn_id)
        return -1;

    return 0;
}

static void
c1_tree_merge_txn(void *item, struct list_head *dst)
{
    struct c1_treetxn *txn = item;

    list_del(&txn->c1txn_list);
    list_add_tail(&txn->c1txn_list, dst);
}
BullseyeCoverageRestore

    static void *
    c1_tree_kvb_next(struct list_head *list)
{
    struct c1_kvb *next;

    next = list_first_entry_or_null(list, typeof(*next), c1kvb_list);

    return next;
}

int
c1_tree_kvb_cmp(void *arg1, void *arg2)
{
    struct c1_kvb *kvb1 = arg1;
    struct c1_kvb *kvb2 = arg2;

    if (kvb1->c1kvb_mutation > kvb2->c1kvb_mutation)
        return 1;

    if (kvb1->c1kvb_mutation < kvb2->c1kvb_mutation)
        return -1;

    return 0;
}

static void
c1_tree_merge_kvb(void *item, struct list_head *dst)
{
    struct c1_kvb *kvb = item;

    list_del(&kvb->c1kvb_list);
    list_add_tail(&kvb->c1kvb_list, dst);
}

static void
c1_tree_replay_merge(
    struct list_head **src,
    struct list_head * dst,
    int                numlogs,
    void *(*nextfunc)(struct list_head *head),
    int (*cmpfunc)(void *arg1, void *arg2),
    void (*mergefunc)(void *arg1, struct list_head *head))
{
    struct list_head *list;
    void *            cur;
    void *            next;
    int               i;
    int               cmp;

    do {
        cur = NULL;

        for (i = 0; i < numlogs; i++) {
            list = src[i];
            if (list_empty(list))
                continue;

            next = nextfunc(list);
            if (!cur) {
                cur = next;
                continue;
            }

            cmp = cmpfunc(cur, next);
            assert(cmp != 0);

            if (cmp > 0)
                cur = next;
        }

        if (cur)
            mergefunc(cur, dst);

    } while (cur);
}

merr_t
c1_tree_replay_process_txn(struct c1 *c1, struct c1_tree *tree)
{
    struct list_head **src;
    merr_t             err;
    int                numlogs;
    int                i, j;
    bool               final;

    final = true;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    src = malloc_array(numlogs, sizeof(*src));
    if (!src)
        return merr(ev(ENOMEM));

    err = 0;

    for (i = 0; i < numlogs; i++) {
        err = c1_log_replay_open(tree->c1t_log[i], C1_REPLAY_METADATA, c1->c1_version);
        if (ev(err))
            goto err_exit;
    }

    for (j = 0; j < numlogs; j++) {
        err = c1_log_replay(tree->c1t_log[j], c1_kvmsgen(c1), c1->c1_version);
        if (ev(err))
            if (ev(merr_errno(err) != ENOENT))
                goto err_exit;
        src[j] = &tree->c1t_log[j]->c1l_txn_list;
    }

    err = 0;

    c1_tree_replay_merge(
        src, &tree->c1t_txn_list, numlogs, c1_tree_txn_next, c1_tree_txn_cmp, c1_tree_merge_txn);

    final = false;

err_exit:
    free(src);
    while (--i >= 0)
        c1_log_replay_close(tree->c1t_log[i], final);

    return err;
}

merr_t
c1_tree_replay_process_kvb(struct c1 *c1, struct c1_tree *tree)
{
    struct list_head **src;
    merr_t             err;
    int                numlogs;
    int                i, j;
    bool               final;

    final = true;

    numlogs = tree->c1t_stripe_width;
    assert(numlogs > 0);

    src = malloc_array(numlogs, sizeof(*src));
    if (!src)
        return merr(ev(ENOMEM));

    err = 0;

    for (i = 0; i < numlogs; i++) {
        err = c1_log_replay_open(tree->c1t_log[i], C1_REPLAY_DATA, c1->c1_version);
        if (ev(err))
            goto err_exit;
    }

    for (j = 0; j < numlogs; j++) {
        err = c1_log_replay(tree->c1t_log[j], c1_kvmsgen(c1), c1->c1_version);
        if (ev(err))
            if (merr_errno(err) != ENOENT)
                goto err_exit;
        err = 0;
        src[j] = &tree->c1t_log[j]->c1l_kvb_list;
    }

    c1_tree_replay_merge(
        src, &tree->c1t_kvb_list, numlogs, c1_tree_kvb_next, c1_tree_kvb_cmp, c1_tree_merge_kvb);

    final = false;

err_exit:
    free(src);
    while (--i >= 0)
        c1_log_replay_close(tree->c1t_log[i], final);

    return err;
}

static void
c1_tree_replay_verify_keycount(struct c1 *c1, struct c1_tree *tree, u64 keycount)
{
    struct c1_kvb *kvb;
    u64            keys;

    keys = 0;

    list_for_each_entry (kvb, &tree->c1t_kvb_list, c1kvb_list) {
        keys += kvb->c1kvb_keycount;
        assert(kvb->c1kvb_data);
    }

    if (keys != keycount)
        hse_log(
            HSE_DEBUG "Log key count %ld replayed %ld",
            (unsigned long)keycount,
            (unsigned long)keys);
}

static merr_t
c1_tree_replay_exec(
    struct c1 *        c1,
    u64                cnid,
    u64                seqno,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    bool               tomb)
{
    struct ikvdb *ikvdb;

    c1_set_kvdb_seqno(c1, seqno);

    /*
     * This function is not reached for a clean c1 unless it is called
     * from unit tests.
     */

    ikvdb = c1_ikvdb(c1);

    return c1_replay_on_ikvdb(c1, ikvdb, cnid, seqno, kt, vt, tomb);
}

#ifdef HSE_BUILD_DEBUG
static void
c1_tree_replay_verify_kvb_list(struct c1_tree *tree)
{
    struct c1_kvb *kvb;
    u64            mutation = 0;

    list_for_each_entry (kvb, &tree->c1t_kvb_list, c1kvb_list) {
        if (mutation && (mutation > kvb->c1kvb_mutation)) {
            hse_log(
                HSE_DEBUG "c1 replay invalid mutation order "
                          "%ld comes after %ld",
                (unsigned long)mutation,
                (unsigned long)kvb->c1kvb_mutation);
        }
        assert(!mutation || mutation <= kvb->c1kvb_mutation);
        mutation = kvb->c1kvb_mutation;
    }
}

static void
c1_tree_replay_verify_txn_list(struct c1_tree *tree)
{
    struct c1_treetxn *txn;
    u64                txnid = 0;

    list_for_each_entry (txn, &tree->c1t_txn_list, c1txn_list) {
        if (txnid && (txnid > txn->c1txn_id)) {
            hse_log(
                HSE_DEBUG "c1 replay invalid transaciton order "
                          "%ld comes after %ld",
                (unsigned long)txnid,
                (unsigned long)txn->c1txn_id);
        }
        assert(!txnid || txnid <= txn->c1txn_id);
        txnid = txn->c1txn_id;
    }
}
#endif

#pragma push_macro("c1_ingest_kvbundle")
#undef c1_ingest_kvbundle

bool
c1_ingest_kvbundle(u64 ingestid, u64 kvmsgen)
{
    if (ingestid == CNDB_INVAL_INGESTID)
        return true;

    if (ingestid == CNDB_DFLT_INGESTID)
        return true;

    if (ingestid && kvmsgen && (kvmsgen > ingestid))
        return true;

    return false;
}

#pragma pop_macro("c1_ingest_kvbundle")

static merr_t
c1_tree_replay_nextkey(
    struct c1 *     c1,
    struct c1_tree *tree,
    void **         nextkey,
    u64             kvmsgen,
    u64             mutation,
    u64             minseqno,
    u64             maxseqno)
{
    char *                 kvtomf;
    struct c1_kvtuple_meta kvtm;
    char *                 vtomf;
    struct c1_vtuple_meta  vtm;
    char *                 mblkomf = NULL;
    struct c1_mblk_meta    mblk;
    struct kvs_ktuple      kt;
    struct kvs_vtuple      vt;
    u64                    seqno;
    u64                    cnid;
    u64                    klen;
    u64                    numval;
    u64                    vlen;
    u64                    i;
    void *                 value;
    void *                 vdata;
    merr_t                 err;
    bool                   tomb;
    u32                    len;

    kvtomf = *nextkey;
    assert(kvtomf);

    err = c1_record_unpack_bytype(kvtomf, C1_TYPE_KVT, c1->c1_version, (union c1_record *)&kvtm);
    if (ev(err))
        return err;

    klen = kvtm.c1kvm_klen;
    cnid = kvtm.c1kvm_cnid;
    kvs_ktuple_init(&kt, kvtm.c1kvm_data, klen);

    if (kvtm.c1kvm_sign != C1_KEY_MAGIC) {
        err = merr(ev(EINVAL));
        hse_log(
            HSE_ERR "%s: c1 replay ktuple signature (%lx-%lx) "
                    "does not math",
            __func__,
            (unsigned long)kvtm.c1kvm_sign,
            (unsigned long)C1_KEY_MAGIC);
        return err;
    }

    numval = kvtm.c1kvm_vcount;
    value = kvtm.c1kvm_data + klen;

    for (i = 0; i < numval; i++) {

        vtomf = value;
        err = c1_record_unpack_bytype(vtomf, C1_TYPE_VT, c1->c1_version, (union c1_record *)&vtm);
        if (ev(err))
            return err;

        vlen = vtm.c1vm_vlen;

        if (vlen && (vtm.c1vm_sign != C1_VAL_MAGIC)) {
            err = merr(ev(EINVAL));
            hse_log(
                HSE_ERR "%s: c1 replay ktuple signature (%lx-%lx) "
                        "does not math",
                __func__,
                (unsigned long)vtm.c1vm_sign,
                (unsigned long)C1_VAL_MAGIC);
            return err;
        }

        seqno = vtm.c1vm_seqno;
        tomb = (vtm.c1vm_tomb == 1) ? true : false;

        err = c1_record_type2len(C1_TYPE_VT, c1->c1_version, &len);
        if (ev(err))
            return err;

        value += len;
        if (vtm.c1vm_logtype == C1_LOG_MBLOCK) {
            mblkomf = vtm.c1vm_data;
            err = c1_record_type2len(C1_TYPE_MBLK, c1->c1_version, &len);
            if (ev(err))
                return err;

            value += len;
        } else {
            value += vlen;
        }

        assert(seqno >= minseqno);
        assert(seqno <= maxseqno);
        assert(c1_kvmsgen(c1) >= CNDB_DFLT_INGESTID || kvmsgen > c1_kvmsgen(c1));

        /*
         * Support for nested c1 replay failure. Ignore all entries
         * having sequence numbers lesser than the one last
         * entered cn(db).
         */
        if (!c1_ingest_seqno(c1, seqno))
            continue;

        if (vtm.c1vm_logtype == C1_LOG_MBLOCK) {
            err = c1_record_unpack_bytype(
                mblkomf, C1_TYPE_MBLK, c1->c1_version, (union c1_record *)&mblk);
            if (ev(err))
                return err;

            err = c1_mblk_get_val(tree->c1t_mblk, mblk.c1mblk_id, mblk.c1mblk_off, &vdata, vlen);
            if (ev(err)) {
                if (merr_errno(err) == ENOENT) {
                    err = 0;
                    continue;
                }

                return err;
            }
        } else {
            vdata = vtm.c1vm_data;
        }

        if (tomb)
            vlen = 0;

        kvs_vtuple_init(&vt, vdata, vlen);

        err = c1_tree_replay_exec(c1, cnid, seqno, &kt, &vt, tomb);

        if (vtm.c1vm_logtype == C1_LOG_MBLOCK)
            c1_mblk_put_val(tree->c1t_mblk, mblk.c1mblk_id, mblk.c1mblk_off, vdata, vlen);
        if (ev(err)) {
            hse_elog(HSE_ERR "%s: c1 kvdb_c1_replay_exec failed: @@e", err, __func__);
            return err;
        }

        if (!i) {
            atomic64_inc(&tree->c1t_numkeys);
            perfc_inc(&c1->c1_pcset_kv, PERFC_BA_C1_KEYR);
            atomic64_add(numval, &tree->c1t_numvals);
        }
        perfc_inc(&c1->c1_pcset_kv, PERFC_BA_C1_VALR);
    }

    assert(value);
    *nextkey = value;

    return 0;
}

static merr_t
c1_tree_replay_kvb_impl(struct c1 *c1, struct c1_tree *tree, struct c1_kvb *kvb)
{
    u64    i;
    merr_t err;
    void * next;

    next = kvb->c1kvb_data;
    assert(next);

    for (i = 0; i < kvb->c1kvb_keycount; i++) {
        err = c1_tree_replay_nextkey(
            c1,
            tree,
            &next,
            kvb->c1kvb_ingestid,
            kvb->c1kvb_mutation,
            kvb->c1kvb_minseqno,
            kvb->c1kvb_maxseqno);
        if (ev(err))
            return err;
    }

    return 0;
}

static merr_t
c1_tree_replay_kvb(struct c1 *c1, struct c1_tree *tree, u64 mutation, u64 txnid)
{
    struct c1_kvb *kvb;
    struct c1_kvb *tmpkvb;
    merr_t         err;
    static u64     ingestid = U64_MAX;

    list_for_each_entry_safe (kvb, tmpkvb, &tree->c1t_kvb_list, c1kvb_list) {

        if ((mutation != (u64)-1) && kvb->c1kvb_mutation > mutation)
            break;

        /* Determine flush boundary based on ingestid. A kv bundle
         * stores the ingestid and all kv bundles appear in c1 log
         * in the order of ingestid. An ingestid corresponds to
         * mutations from a single c0kvms. A change in ingestid
         * indicates that we are crossing c0kvms and the bundles till
         * that point (if any) can be flushed as an independent entity.
         */
        if (ingestid != U64_MAX && kvb->c1kvb_ingestid != ingestid &&
            c1_ingest_kvbundle(c1_kvmsgen(c1), ingestid)) {
            err = ikvdb_flush(c1_ikvdb(c1));
            if (ev(err))
                return err;
        }

        ingestid = kvb->c1kvb_ingestid;

        /* For tx replay, replay all kv bundles containing this txnid.
         * For non-tx replay, replay all kv bundles having mutation
         * no. <= to the mutation no. passed by the caller.
         */
        if ((txnid && txnid == kvb->c1kvb_txnid) ||
            (!txnid && !kvb->c1kvb_txnid && kvb->c1kvb_mutation <= mutation)) {

            assert(!txnid || (txnid && kvb->c1kvb_mutation <= mutation));

            if (c1_ingest_kvbundle(c1_kvmsgen(c1), kvb->c1kvb_ingestid)) {
                err = c1_tree_replay_kvb_impl(c1, tree, kvb);
                if (ev(err))
                    return err;
            }

            list_del(&kvb->c1kvb_list);
            free(kvb->c1kvb_data);
            free(kvb);
        }
    }

    return 0;
}

static merr_t
c1_tree_replay_txn(struct c1 *c1, struct c1_tree *tree)
{
    struct c1_treetxn *txn;
    struct c1_treetxn *tmptxn;
    merr_t             err;

    list_for_each_entry_safe (txn, tmptxn, &tree->c1t_txn_list, c1txn_list) {
        list_del(&txn->c1txn_list);

        /*
         * Process non-tranactional ingests which arrived
         * before a given transaction.
         */
        err = c1_tree_replay_kvb(c1, tree, txn->c1txn_mutation, 0);
        if (ev(err))
            return err;

        /*
         * Then process the contents of this transaction
         */
        err = c1_tree_replay_kvb(c1, tree, txn->c1txn_mutation, txn->c1txn_id);
        if (ev(err))
            return err;

        free(txn);
    }

    return 0;
}

static void
c1_tree_replay_release_txnkvb(struct c1_tree *tree)
{
    struct c1_kvb *kvb;
    struct c1_kvb *tmpkvb;

    list_for_each_entry_safe (kvb, tmpkvb, &tree->c1t_kvb_list, c1kvb_list) {
        assert(kvb->c1kvb_txnid);
        list_del(&kvb->c1kvb_list);
        free(kvb->c1kvb_data);
        free(kvb);
    }
}

merr_t
c1_tree_replay(struct c1 *c1, struct c1_tree *tree)
{
    merr_t err;
    u64    ingestedkeys;
    u64    replayedkeys;

    if (c1_is_clean(c1)) {
        hse_log(
            HSE_DEBUG "c1 replay "
                      "Tree %p vers %ld-%ld Clean tree, no replay needed",
            tree,
            (unsigned long)tree->c1t_seqno,
            (unsigned long)tree->c1t_gen);
        c1_tree_mark_empty(tree);
        return 0;
    }

    hse_log(
        HSE_DEBUG "c1 Replaying Tree %p vers %ld-%ld",
        tree,
        (unsigned long)tree->c1t_seqno,
        (unsigned long)tree->c1t_gen);

    perfc_inc(&c1->c1_pcset_tree, PERFC_BA_C1_TREPL);

    /*
     * Gather all transaction information from the logs
     * of the given tree. Sort the transactions based on
     * their TXNID to avoid out-of-order processing.
     */
    INIT_LIST_HEAD(&tree->c1t_txn_list);
    err = c1_tree_replay_process_txn(c1, tree);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 replay processing TXN failed: @@e", err, __func__);
        return err;
    }

#ifdef HSE_BUILD_DEBUG
    /* Validate if the transaction list contains out-of-order
     * entries.
     */
    c1_tree_replay_verify_txn_list(tree);
#endif

    c1_tree_keycount(tree, &ingestedkeys, &replayedkeys);

    /*
     * Gather all key/value tuples saved in the logs, Arrange them
     * in the order of their  order of arrival.
     */
    INIT_LIST_HEAD(&tree->c1t_kvb_list);
    err = c1_tree_replay_process_kvb(c1, tree);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 replay processing KVB failed: @@e", err, __func__);
        return err;
    }

#ifdef HSE_BUILD_DEBUG
    /* Validate if the kv bundlelist contains out-of-order
     * entries.
     */
    c1_tree_replay_verify_kvb_list(tree);
#endif

    c1_tree_replay_verify_keycount(c1, tree, replayedkeys);

    /*
     * If there is no key/value then the tree is empty, mark
     * it so and return.
     */
    if (list_empty(&tree->c1t_kvb_list)) {
        hse_log(HSE_DEBUG "c1 Empty tree, no replay needed");
        c1_tree_mark_empty(tree);
        return 0;
    }

    err = c1_mblk_create(c1_journal_get_mp(c1->c1_jrnl), &tree->c1t_mblk);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1_mblk_create failed: @@e", err, __func__);
        return err;
    }

    /*
     * Process transactions first. The key/value(s) which are not
     * part of transactions, but arrive before a transaction are
     * processed first before the transaction.
     */
    err = c1_tree_replay_txn(c1, tree);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1 replay TXN failed: @@e", err, __func__);
        c1_mblk_destroy(tree->c1t_mblk);
        return err;
    }

    /*
     * Process key/value(s) which are not part of any tranaction.
     */
    err = c1_tree_replay_kvb(c1, tree, (u64)-1, 0);
    if (ev(err)) {
        c1_mblk_destroy(tree->c1t_mblk);
        hse_elog(HSE_ERR "%s: c1 replay KVB failed: @@e", err, __func__);
        return err;
    }

    /* There are can be a subset of key/value bundles which are part
     * of one or more transactions whose commit status did not make
     * it to the peristent log. They are discarded without replaying
     * and their memory will be freed.
     */
    c1_tree_replay_release_txnkvb(tree);

    c1_mblk_destroy(tree->c1t_mblk);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: kvdb sync failed: @@e", err, __func__);
        return err;
    }

    hse_log(
        HSE_WARNING "c1 replay summary tree %p ver %ld-%ld "
                    "Logged keys %ld Keys found in replay %ld "
                    "Keys replayed %ld",
        tree,
        (unsigned long)tree->c1t_seqno,
        (unsigned long)tree->c1t_gen,
        (unsigned long)ingestedkeys,
        (unsigned long)replayedkeys,
        (long)atomic64_read(&tree->c1t_numkeys));

    assert(list_empty(&tree->c1t_txn_list));
    assert(list_empty(&tree->c1t_kvb_list));

    return 0;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_tree_utils_ut_impl.i"
#endif
