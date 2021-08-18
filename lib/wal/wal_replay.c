/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/slab.h>
#include <hse_util/bonsai_tree.h>
#include <hse_util/rmlock.h>

#include <rbtree/rbtree.h>

#include <hse_ikvdb/cndb.h>

#include "wal.h"
#include "wal_replay.h"
#include "wal_file.h"
#include "wal_mdc.h"
#include "wal_omf.h"


struct wal_replay_gen {
    struct list_head       rg_link HSE_ALIGNED(SMP_CACHE_BYTES);

    struct mutex           rg_lock;
    struct rb_root         rg_root;

    struct wal_minmax_info rg_info HSE_ALIGNED(SMP_CACHE_BYTES);
    uint64_t               rg_gen;

    uint64_t               rg_krcnt;
    uint64_t               rg_maxseqno;
    uint64_t               rg_bytes;
};

struct wal_replay_work {
    struct work_struct          rw_work;
    struct wal_replay          *rw_rep;
    struct wal_replay_gen_info *rw_rginfo;
    merr_t                      rw_err;
};

struct wal_replay {
    struct list_head            r_head HSE_ALIGNED(SMP_CACHE_BYTES);
    struct kmem_cache          *r_cache;

    struct kmem_cache          *r_txm_cache;
    struct rb_root              r_txm_root;
    struct rb_root              r_txcid_root;
    uint64_t                    r_maxcid;

    atomic_t                    r_leader;
    atomic_t                    r_vdone;
    atomic64_t                  r_verr;

    struct wal                 *r_wal HSE_ALIGNED(SMP_CACHE_BYTES);
    struct ikvdb_kvs_hdl       *r_ikvsh;
    struct workqueue_struct    *r_wq;

    struct wal_replay_info     *r_info;
    struct wal_replay_gen_info *r_ginfo;
    uint32_t                    r_cnt;

    struct rmlock               r_txm_lock HSE_ALIGNED(SMP_CACHE_BYTES);
};

struct wal_rec_iter {
    struct kmem_cache      *rcache;
    struct wal_replay_work *rw;
    const char             *buf;
    uint64_t                gen;
    off_t                   curoff;
    off_t                   soff;
    off_t                   eoff;
    size_t                  size;
    merr_t                  err;
    bool                    eof;
};


/* Forward declarations */
#ifndef NDEBUG
static void
wal_replay_dump_info(struct wal_replay *rep);

static void
wal_replay_dump_rgen(struct wal_replay *rep);
#endif

static struct wal_replay_gen *
wal_replay_gen_get(struct wal_replay *rep, uint64_t gen);

static struct wal_replay_gen *
wal_replay_gen_getbyseqno(struct wal_replay *rep, uint64_t seqno);

static merr_t
wal_replay_open(struct wal *wal, struct wal_replay_info *rinfo, struct wal_replay **rep_out)
{
    struct wal_replay *rep;
    merr_t err;

    rep = aligned_alloc(alignof(*rep), sizeof(*rep));
    if (!rep)
        return merr(ENOMEM);
    memset(rep, 0, sizeof(*rep));

    rep->r_cache = kmem_cache_create("wal-reprec", sizeof(struct wal_rec),
                                     alignof(struct wal_rec), 0, NULL);
    if (!rep->r_cache) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    rep->r_txm_cache = kmem_cache_create("wal-reptxm", sizeof(struct wal_txmeta_rec),
                                        alignof(struct wal_txmeta_rec), 0, NULL);
    if (!rep->r_txm_cache) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    err = ikvdb_wal_replay_open(wal_ikvdb(wal), &rep->r_ikvsh);
    if (err)
        goto err_exit;

    rep->r_wal = wal;
    rep->r_info = rinfo;
    INIT_LIST_HEAD(&rep->r_head);

    rmlock_init(&rep->r_txm_lock);
    rep->r_txm_root = RB_ROOT;
    rep->r_txcid_root = RB_ROOT;

    atomic_set(&rep->r_leader, 0);
    atomic_set(&rep->r_vdone, 0);
    atomic64_set(&rep->r_verr, 0);

    *rep_out = rep;

    return 0;

err_exit:
    kmem_cache_destroy(rep->r_txm_cache);
    kmem_cache_destroy(rep->r_cache);
    free(rep);

    return err;
}

static void
wal_replay_close(struct wal_replay *rep, bool failed)
{
    struct wal_replay_gen *cgen, *ngen;
    struct wal_txmeta_rec *ctxm, *ntxm;
    struct wal *wal;
    int i;

    if (!rep)
        return;

    wal = rep->r_wal;

    ikvdb_wal_replay_close(wal_ikvdb(wal), rep->r_ikvsh);

    list_for_each_entry_safe(cgen, ngen, &rep->r_head, rg_link) {
        struct rb_root *root = &cgen->rg_root;
        struct wal_rec *cur, *next;

        rbtree_postorder_for_each_entry_safe(cur, next, root, node)
            kmem_cache_free(rep->r_cache, cur);

        list_del_init(&cgen->rg_link);
        free(cgen);
    }

    rbtree_postorder_for_each_entry_safe(ctxm, ntxm, &rep->r_txm_root, node)
        kmem_cache_free(rep->r_txm_cache, ctxm);

    for (i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo = rep->r_ginfo + i;

        rbtree_postorder_for_each_entry_safe(ctxm, ntxm, &rginfo->txm_root, node)
            kmem_cache_free(rep->r_txm_cache, ctxm);
    }

    wal_fileset_replay_free(wal_fset(wal), failed);

    kmem_cache_destroy(rep->r_txm_cache);
    kmem_cache_destroy(rep->r_cache);
    rmlock_destroy(&rep->r_txm_lock);

    free(rep);
}


/*
 * WAL record iterator interfaces
 */

static void
wal_rec_iter_init(struct wal_replay_work *rw, struct wal_rec_iter *iter)
{
    iter->buf = rw->rw_rginfo->buf;
    iter->gen = rw->rw_rginfo->gen;
    iter->curoff = 0;
    iter->soff = rw->rw_rginfo->soff;
    iter->eoff = rw->rw_rginfo->eoff;
    iter->eof = false;
    iter->rcache = rw->rw_rep->r_cache;
    iter->size = rw->rw_rginfo->size;
    iter->err = 0;
    iter->rw = rw;
}

#ifndef NDEBUG
static bool
wal_rec_iter_eof(struct wal_rec_iter *iter)
{
    return iter->eof;
}
#endif

static struct wal_txmeta_rec *
wal_txmrec_rb_search(struct wal_replay *rep, uint64_t txid)
{
    struct rb_root *root = &rep->r_txm_root;
    struct rb_node *node = root->rb_node;

    while (node) {
        struct wal_txmeta_rec *this = container_of(node, struct wal_txmeta_rec, node);

        if (txid < this->txid)
            node = node->rb_left;
        else if (txid > this->txid)
            node = node->rb_right;
        else
            return this;
    }

    return NULL;
}

static struct wal_rec *
wal_rec_iter_next(struct wal_rec_iter *iter)
{
    struct wal_rec *rec;
    const char *buf;

next_rec:
    if (iter->eof)
        return NULL;

    buf = iter->buf;
    buf += iter->curoff;

    if ((iter->eoff != 0 && (iter->curoff + iter->soff >= iter->eoff)) ||
        (iter->curoff + iter->soff >= iter->size)) {
        iter->eof = true;
        return NULL;
    }

    iter->curoff += wal_reclen_total(buf);

    if (wal_rec_skip(buf) || wal_rec_is_txnmeta(buf))
        goto next_rec;

    rec = kmem_cache_alloc(iter->rcache);
    if (!rec) {
        iter->err = merr(ENOMEM);
        return NULL;
    }

    wal_rec_unpack(buf, rec);

    if (rec->hdr.type == WAL_RT_TX) {
        struct wal_replay *rep = iter->rw->rw_rep;
        struct wal_txmeta_rec *trec;
        void *cookie;

        rmlock_rlock(&rep->r_txm_lock, &cookie);
        trec = wal_txmrec_rb_search(rep, rec->txid);
        rmlock_runlock(cookie);

        if (!trec || trec->cid > rep->r_maxcid) {
            kmem_cache_free(iter->rcache, rec);
            goto next_rec;
        }

        /* Update seqno and gen based on the tx commit record */
        rec->seqno = trec->cseqno;
        rec->hdr.gen = trec->gen;
        assert(rec->hdr.rid <= trec->rid);
    } else if (rec->hdr.type == WAL_RT_NONTX) {
        struct wal_replay *rep = iter->rw->rw_rep;
        struct wal_replay_gen *rgen = wal_replay_gen_getbyseqno(rep, rec->seqno);

        if (rgen)
            rec->hdr.gen = rgen->rg_gen;
    }

    return rec;
}

static merr_t
wal_txmeta_rb_insert(struct rb_root *root, struct wal_txmeta_rec *trec)
{
    struct rb_node **new = &root->rb_node;
    struct rb_node  *parent = NULL;

    while (*new) {
        struct wal_txmeta_rec *this = container_of(*new, struct wal_txmeta_rec, node);

        parent = *new;

        if (trec->txid < this->txid)
            new = &((*new)->rb_left);
        else if (trec->txid > this->txid)
            new = &((*new)->rb_right);
        else
            return merr(EBUG);
    }

    rb_link_node(&trec->node, parent, new);
    rb_insert_color(&trec->node, root);

    return 0;
}

static merr_t
wal_txcid_rb_insert(struct rb_root *root, struct wal_txmeta_rec *trec)
{
    struct rb_node **new = &root->rb_node;
    struct rb_node  *parent = NULL;

    while (*new) {
        struct wal_txmeta_rec *this = container_of(*new, struct wal_txmeta_rec, cid_node);

        parent = *new;

        if (trec->cid < this->cid) {
            new = &((*new)->rb_left);
            assert(trec->cseqno < this->cseqno);
        } else if (trec->cid > this->cid) {
            new = &((*new)->rb_right);
            assert(trec->cseqno > this->cseqno);
        } else {
            assert(trec->cseqno == this->cseqno);
            return merr(EBUG);
        }
    }

    rb_link_node(&trec->cid_node, parent, new);
    rb_insert_color(&trec->cid_node, root);

    return 0;
}

static merr_t
wal_recs_validate(struct wal_replay_work *rw)
{
    struct wal_replay *rep = rw->rw_rep;
    struct wal_minmax_info *info;
    struct wal_replay_gen_info *rginfo = rw->rw_rginfo;
    off_t curoff = 0, rgeoff = 0;
    uint64_t gen = rginfo->gen, recoff = 0;
    const char *buf = rginfo->buf;
    bool valid, eorg = false;
    merr_t err = 0;

    info = rginfo->info_valid ? NULL : &rginfo->info;

    while ((valid = wal_rec_is_valid(buf, curoff + rginfo->soff, rginfo->size, &recoff,
                                     gen, info, &eorg))) {
        size_t len = wal_reclen_total(buf);

        if (wal_rec_is_txncommit(buf)) {
            struct wal_txmeta_rec *trec;

            trec = kmem_cache_alloc(rep->r_txm_cache);
            if (!trec) {
                err = merr(ENOMEM);
                goto exit;
            }

            wal_txn_rec_unpack(buf, trec);
            trec->fileoff = curoff + rginfo->soff;

            if (trec->cseqno > rep->r_info->seqno) {
                spin_lock(&rginfo->txm_lock);
                err = wal_txmeta_rb_insert(&rginfo->txm_root, trec);
                if (HSE_LIKELY(!err))
                    err = wal_txcid_rb_insert(&rginfo->txcid_root, trec);
                spin_unlock(&rginfo->txm_lock);

                if (err) {
                    kmem_cache_free(rep->r_txm_cache, trec);
                    goto exit;
                }
            } else {
                kmem_cache_free(rep->r_txm_cache, trec); /* Ingested txn */
            }
        }

        curoff += len;

        if (eorg && curoff > rgeoff)
            rgeoff = curoff;

        if ((rginfo->eoff != 0 && (curoff + rginfo->soff >= rginfo->eoff)) ||
            curoff + rginfo->soff >= rginfo->size) {
            break; /* end of wal file */
        }

        buf += len;
        recoff += len;
    }

    if (rginfo->eoff && !valid) {
        assert(valid);
        hse_log(HSE_CRIT "WAL replay: Corrupted record found in gen %lu file %d, "
                "off (%lu:%lu:%lu), failing replay",
                gen, rginfo->fileid, curoff, rginfo->eoff, rgeoff);
        err = merr(EBADMSG);
        goto exit;
    }

    rgeoff += rginfo->soff;
    assert(rginfo->eoff == 0 || rginfo->eoff == rgeoff);

    /* An ending offset of 0 implies that the crash occurred before updating file stats */
    rginfo->eoff = rginfo->eoff ? : rgeoff;

    rginfo->info_valid = true;

exit:
    atomic_inc(&rep->r_vdone);
    if (err)
        atomic64_set(&rep->r_verr, err);

    return err;
}



/*
 * WAL replay gen interfaces
 */

static void
wal_replay_gen_init(struct wal_replay_gen *rgen, struct wal_replay_gen_info *rginfo)
{
    INIT_LIST_HEAD(&rgen->rg_link);
    mutex_init(&rgen->rg_lock);
    rgen->rg_root = RB_ROOT;

    rgen->rg_gen = rginfo->gen;
    rgen->rg_info = rginfo->info;
    rgen->rg_krcnt = 0;
    rgen->rg_maxseqno = 0;
    rgen->rg_bytes = 0;
}

static void
wal_replay_gen_update(struct wal_replay_gen *rgen, struct wal_replay_gen_info *rginfo)
{
    struct wal_minmax_info *info;

    if (!rgen || !rginfo->info_valid)
        return;

    info = &rgen->rg_info;
    info->min_seqno = min_t(uint64_t, info->min_seqno, rginfo->info.min_seqno);
    info->max_seqno = max_t(uint64_t, info->max_seqno, rginfo->info.max_seqno);
    info->min_gen = min_t(uint64_t, info->min_gen, rginfo->info.min_gen);
    info->max_gen = max_t(uint64_t, info->max_gen, rginfo->info.max_gen);
    info->min_txid = min_t(uint64_t, info->min_txid, rginfo->info.min_txid);
    info->max_txid = max_t(uint64_t, info->max_txid, rginfo->info.max_txid);
}

static struct wal_replay_gen *
wal_replay_gen_get(struct wal_replay *rep, uint64_t gen)
{
    struct wal_replay_gen *rgen;

    list_for_each_entry(rgen, &rep->r_head, rg_link) {
        if (rgen->rg_gen == gen)
            return rgen;
    }

    return NULL;
}

static struct wal_replay_gen *
wal_replay_gen_getbyseqno(struct wal_replay *rep, uint64_t seqno)
{
    struct wal_replay_gen *rgen;

    list_for_each_entry(rgen, &rep->r_head, rg_link) {
        if (seqno >= rgen->rg_info.min_seqno && seqno <= rgen->rg_info.max_seqno) {
            return rgen;
        }
    }

    return NULL;
}

merr_t
wal_replay_gen_impl(struct wal_replay *rep, struct wal_replay_gen *rgen, bool flags)
{
    struct rb_root *root = &rgen->rg_root;
    struct rb_node *node;
    struct ikvdb *ikvdb = wal_ikvdb(rep->r_wal);
    struct ikvdb_kvs_hdl *ikvsh = rep->r_ikvsh;
    merr_t err;

    node = rb_first(root);
    while (node) {
        struct wal_rec *rec = rb_entry(node, struct wal_rec, node);
        struct kvs_ktuple *kt = &rec->kt;
        struct kvs_vtuple *vt = &rec->vt;

        node = rb_next(node);

        assert(rec->hdr.type == WAL_RT_NONTX || rec->hdr.type == WAL_RT_TX);

        kt->kt_flags = flags;

        switch (rec->op) {
          case WAL_OP_PUT:
            err = ikvdb_wal_replay_put(ikvdb, ikvsh, rec->cnid, rec->seqno, kt, vt);
            break;

          case WAL_OP_DEL:
            err = ikvdb_wal_replay_del(ikvdb, ikvsh, rec->cnid, rec->seqno, kt);
            break;

          case WAL_OP_PDEL:
            err = ikvdb_wal_replay_prefix_del(ikvdb, ikvsh, rec->cnid, rec->seqno, kt);
            break;

          default:
            err = merr(EINVAL);
            break;
        }

        if (HSE_UNLIKELY(err)) {
            struct wal_rec *cur, *next;

            hse_log(HSE_CRIT "WAL replay: Unrecognized record op %d in gen %lu, failing replay",
                    rec->op, rgen->rg_gen);

            rbtree_postorder_for_each_entry_safe(cur, next, root, node)
                kmem_cache_free(rep->r_cache, cur);

            return err;
        }

        rgen->rg_maxseqno = max_t(uint64_t, rgen->rg_maxseqno, rec->seqno);

        rb_erase(&rec->node, root);
        kmem_cache_free(rep->r_cache, rec);
        rgen->rg_krcnt++;
    }

    return 0;
}


/*
 * General WAL replay interfaces
 */

static merr_t
wal_replay_core(struct wal_replay *rep)
{
    struct wal_replay_gen *cur, *next;
    struct ikvdb *ikvdb;
    uint32_t flags;
    uint64_t maxseqno = 0;

    ikvdb = wal_ikvdb(rep->r_wal);
    flags = HSE_BTF_MANAGED; /* Replay with MANAGED flag to let c0 share the mmaped wal files */

    /* Set c0sk to wal replay mode. This disables the c0kvms_should ingest() check and
     * allow us to take control of the c0kvms boundaries. Also, the seqno bump for reserved
     * seqno and LC are also skipped.
     */
    ikvdb_wal_replay_enable(ikvdb);

    cur = list_first_entry_or_null(&rep->r_head, typeof(*cur), rg_link);
    if (cur && cur->rg_bytes != 0) {
        if (ikvdb_wal_replay_size_set(ikvdb, rep->r_ikvsh, cur->rg_bytes))
            ikvdb_sync(ikvdb, HSE_FLAG_SYNC_ASYNC);
    }

    list_for_each_entry_safe(cur, next, &rep->r_head, rg_link) {
        merr_t err;
        bool   flush = false, last_entry;

        /* Set the c0kvms gen to the gen that's about to be replayed */
        ikvdb_wal_replay_gen_set(ikvdb, cur->rg_gen);

        err = wal_replay_gen_impl(rep, cur, flags);
        if (err) {
            ikvdb_wal_replay_disable(ikvdb);
            return err;
        }

        if (next && next->rg_bytes != 0)
            flush = ikvdb_wal_replay_size_set(ikvdb, rep->r_ikvsh, next->rg_bytes);

        last_entry = !next;

        if (flush || cur->rg_krcnt || last_entry) {
            err = ikvdb_sync(ikvdb, last_entry ? 0 : HSE_FLAG_SYNC_ASYNC);
            if (err) {
                ikvdb_wal_replay_disable(ikvdb);
                return err;
            }
        }

        maxseqno = max_t(uint64_t, maxseqno, cur->rg_maxseqno);

        hse_log(HSE_NOTICE "WAL replay: Gen %lu, maxseqno %lu replayed %lu keys",
                cur->rg_gen, maxseqno, cur->rg_krcnt);

        list_del_init(&cur->rg_link);
        free(cur);
    }

    /* Set ikvdb seqno to the max seqno seen during replay */
    ikvdb_wal_replay_seqno_set(ikvdb, maxseqno);

    ikvdb_wal_replay_disable(ikvdb);

    ikvdb_wal_replay_size_reset(rep->r_ikvsh);

    return ikvdb_sync(ikvdb, 0); /* Sync a final time after restoring all replay settings */
}

static merr_t
wal_replay_consolidate(struct wal_replay *rep)
{
    struct wal_replay_gen *prev_rgen = NULL, *cur, *next;
    merr_t err = 0;
    uint64_t prev_gen = 0;
    uint64_t pmax_seqno = 0;
    int i;

    for (i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo;

        rginfo = rep->r_ginfo + i;

        if (prev_gen != rginfo->gen) {
            struct wal_replay_gen *rgen;

            assert(rginfo->gen > prev_gen);

            rgen = aligned_alloc(alignof(*rgen), sizeof(*rgen));
            if (!rgen) {
                err = merr(ENOMEM);
                break;
            }

            wal_replay_gen_init(rgen, rginfo);
            list_add_tail(&rgen->rg_link, &rep->r_head);
            prev_gen = rginfo->gen;
            prev_rgen = rgen;
        } else {
            wal_replay_gen_update(prev_rgen, rginfo);
        }
    }

    if (err) {
        list_for_each_entry_safe(cur, next, &rep->r_head, rg_link) {
            list_del_init(&cur->rg_link);
            free(cur);
        }

        return err;
    }

    /* Fix seqno bounds. Set min bound of a gen based on the max bound of the previous gen */
    list_for_each_entry(cur, &rep->r_head, rg_link) {
        uint64_t cmin_seqno = cur->rg_info.min_seqno;
        uint64_t cmax_seqno = cur->rg_info.max_seqno;

        if (cmin_seqno == UINT64_MAX && cmax_seqno == 0) {
            if (cur == list_last_entry(&rep->r_head, typeof(*cur), rg_link) && pmax_seqno > 0) {
                cur->rg_info.min_seqno = pmax_seqno + 1;
                cur->rg_info.max_seqno = UINT64_MAX;
            }
            continue; /* neither commit records nor non-tx recs in this gen, skip it */
        }

        if (cmin_seqno <= pmax_seqno)
            cur->rg_info.min_seqno = pmax_seqno + 1;

        pmax_seqno = cmax_seqno;
    }

    return 0;
}

static merr_t
wal_txmeta_gen_update(struct wal_replay *rep)
{
    struct rb_root *root;
    struct rb_node *cnode, *nnode;
    struct wal_txmeta_rec *trec;
    merr_t err = 0;
    int i;
    uint64_t prevcid, curcid;

    rmlock_wlock(&rep->r_txm_lock);

    for (i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo = rep->r_ginfo + i;
        struct rb_root *cid_root;

        spin_lock(&rginfo->txm_lock);

        root = &rginfo->txm_root;
        cid_root = &rginfo->txcid_root;

        cnode = rb_first(root);

        while (cnode) {
            nnode = rb_next(cnode);

            trec = rb_entry(cnode, struct wal_txmeta_rec, node);

            rb_erase(&trec->node, root);
            rb_erase(&trec->cid_node, cid_root);

            if (trec->fileoff < rginfo->eoff) {
                struct wal_replay_gen *rgen = wal_replay_gen_getbyseqno(rep, trec->cseqno);

                if (rgen)
                    trec->gen = rgen->rg_gen;

                err = wal_txmeta_rb_insert(&rep->r_txm_root, trec);
                if (HSE_LIKELY(!err)) {
                    err = wal_txcid_rb_insert(&rep->r_txcid_root, trec);
                    if (err)
                        break;
                }
            } else {
                kmem_cache_free(rep->r_txm_cache, trec);
            }

            cnode = nnode;
        }

        if (HSE_LIKELY(!err)) {
            rginfo->txm_root = RB_ROOT;
            rginfo->txcid_root = RB_ROOT;
        }

        spin_unlock(&rginfo->txm_lock);
    }

    if (HSE_LIKELY(!err)) {
        root = &rep->r_txcid_root;
        cnode = rb_first(root);
        rep->r_maxcid = prevcid = curcid = 0;

        while (cnode) {
            trec = rb_entry(cnode, struct wal_txmeta_rec, cid_node);
            curcid = trec->cid;

            if (prevcid != 0 && prevcid + 1 != curcid) {
                rep->r_maxcid = prevcid;
                break;
            }

            prevcid = curcid;
            cnode = rb_next(cnode);
        }

        if (rep->r_maxcid == 0)
            rep->r_maxcid = curcid;
    }

    rmlock_wunlock(&rep->r_txm_lock);

    return err;
}

static merr_t
wal_rec_rb_insert(struct wal_replay_gen *rgen, struct wal_rec *rec)
{
    struct rb_root  *root = &rgen->rg_root;
    struct rb_node **new = &root->rb_node;
    struct rb_node  *parent = NULL;

    while (*new) {
        struct wal_rec *this = container_of(*new, struct wal_rec, node);

        parent = *new;

        if (rec->hdr.rid < this->hdr.rid)
            new = &((*new)->rb_left);
        else if (rec->hdr.rid > this->hdr.rid)
            new = &((*new)->rb_right);
        else
            return merr(EBUG);
    }

    rb_link_node(&rec->node, parent, new);
    rb_insert_color(&rec->node, root);

    return 0;
}

static void
wal_replay_worker(struct work_struct *work)
{
    struct wal_replay_work     *rw;
    struct wal_replay_gen      *rgen;
    struct wal_replay_gen_info *rginfo;
    struct wal_replay          *rep;
    struct wal_rec_iter         iter;
    struct wal_rec             *rec;
    uint64_t                    nrecs = 0, ntxrecs = 0, nskipped = 0;
    merr_t                      err;

    rw = container_of(work, struct wal_replay_work, rw_work);

    err = wal_recs_validate(rw);
    if (err) {
        rw->rw_err = err;
        return;
    }

    rep = rw->rw_rep;

    /* Wait for the txn commit processing of all the wal files to complete. This is
     * a must to guarantee txn atomicity when replaying txn mutations.
     */
    while (atomic_read(&rep->r_vdone) < rep->r_cnt)
        usleep(333);

    /* Do not proceed further if there's a failed record validation. Add a force flag
     * later which can replay mutations until the corrupted record.
     */
    rw->rw_err = atomic64_read(&rep->r_verr);
    if (rw->rw_err)
        return;

    /* Elect a leader thread to do replay stats consolidation and fix target gen */
    if (atomic_inc_acq(&rep->r_leader) == 1) {
        err = wal_replay_consolidate(rep);
        if (HSE_LIKELY(!err)) {
            /*
             * Fix target gen for txns based on the consolidated seqno bounds
             * determined by wal_replay_consolidate(). This ensures that the seqno
             * ordering is preserved across c0kvmses.
             */
            err = wal_txmeta_gen_update(rep);
        }

        if (err)
            atomic64_set(&rep->r_verr, err);

        while (atomic_read(&rep->r_leader) < rep->r_cnt)
            cpu_relax();

        atomic_set_rel(&rep->r_leader, 0);
    }

    while (atomic_read(&rep->r_leader) > 0)
        usleep(333);

    rw->rw_err = atomic64_read(&rep->r_verr);
    if (rw->rw_err)
        return;

    rginfo = rw->rw_rginfo;
    wal_rec_iter_init(rw, &iter);

    rgen = wal_replay_gen_get(rep, rginfo->gen);

    while ((rec = wal_rec_iter_next(&iter))) {
        struct wal_replay_gen *trgen = rgen;
        uint64_t gen = rec->hdr.gen;
        uint64_t seqno = rec->seqno;

        /* Add record to the right rgen tree */
        if (gen != trgen->rg_gen)
            trgen = wal_replay_gen_get(rep, gen);

        if (!trgen || seqno <= rep->r_info->seqno) {
            nskipped++;
            kmem_cache_free(rep->r_cache, rec);
            continue; /* skip this rec */
        }

        mutex_lock(&trgen->rg_lock);
        err = wal_rec_rb_insert(trgen, rec);
        mutex_unlock(&trgen->rg_lock);
        if (err) {
            rw->rw_err = err;
            break;
        }

        trgen->rg_bytes += (sizeof(struct bonsai_node) + sizeof(struct bonsai_kv) +
            sizeof(struct bonsai_val) + rec->kt.kt_len + kvs_vtuple_vlen(&rec->vt));

        (rec->hdr.type == WAL_RT_TX) ? ntxrecs++ : nrecs++;
    }

    if (iter.err && rw->rw_err == 0)
        rw->rw_err = iter.err;

    if (rw->rw_err)
        return;

    hse_log(HSE_NOTICE "WAL replay: Gen %lu fileid %d nrecs %lu ntxrecs %lu nskipped %lu",
            rginfo->gen, rginfo->fileid, nrecs, ntxrecs, nskipped);

#ifndef NDEBUG
    assert(wal_rec_iter_eof(&iter));
#endif
}

static merr_t
wal_replay_prepare(struct wal_replay *rep)
{
    struct wal_replay_work *rw;
    int i;
    merr_t err = 0;

    /* The no. of worker threads must not be lower than rep->r_cnt.
     * More details in the replay worker code
     */
    rep->r_wq = alloc_workqueue("wal_replay_wq", 0, rep->r_cnt);
    if (!rep->r_wq)
        return merr(ENOMEM);

    rw = calloc(rep->r_cnt, sizeof(*rw));
    if (!rw) {
        destroy_workqueue(rep->r_wq);
        return merr(ENOMEM);
    }

    for (i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo = rep->r_ginfo + i;

        INIT_WORK(&rw[i].rw_work, wal_replay_worker);
        rw[i].rw_rep = rep;
        rw[i].rw_err = 0;
        rw[i].rw_rginfo = rginfo;

        queue_work(rep->r_wq, &rw[i].rw_work);
    }

    flush_workqueue(rep->r_wq);
    destroy_workqueue(rep->r_wq);

    for (i = 0; i < rep->r_cnt; i++) {
        if (rw[i].rw_err)
            err = rw[i].rw_err;
    }

    free(rw);

    return err;
}

merr_t
wal_replay(struct wal *wal, struct wal_replay_info *rinfo)
{
    struct wal_replay *rep = NULL;
    merr_t err = 0;

    if (wal_is_rdonly(wal) || wal_is_clean(wal))
        return 0; /* clean shutdown */

    err = wal_replay_open(wal, rinfo, &rep);
    if (err)
        return err;

    err = wal_fileset_replay(wal_fset(wal), rinfo, &rep->r_cnt, &rep->r_ginfo);
    if (err)
        goto exit;

    if (rep->r_cnt == 0) /* Nothing to replay */
        goto exit;

#ifndef NDEBUG
    hse_log(HSE_NOTICE "WAL replay: Info: ");
    wal_replay_dump_info(rep);
#endif

    err = wal_replay_prepare(rep);
    if (err)
        goto exit;

#ifndef NDEBUG
    hse_log(HSE_NOTICE "WAL replay: Gen info: ");
    wal_replay_dump_rgen(rep);
#endif

    err = wal_replay_core(rep);
    if (err)
        goto exit;

exit:
    wal_replay_close(rep, !!err);

    return err;
}

#ifndef NDEBUG
static void
wal_replay_dump_info(struct wal_replay *rep)
{
    hse_log(HSE_NOTICE "WAL replay: Entry count: %u", rep->r_cnt);

    for (int i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo;
        struct wal_minmax_info *info;

        hse_log(HSE_NOTICE "WAL replay: Entry %u", i);

        rginfo = rep->r_ginfo + i;
        info = &rginfo->info;

        hse_log(HSE_NOTICE "WAL replay: Gen %lu Fileid %u Seqno (%lu : %lu) gen (%lu : %lu) "
                "txhorizon (%lu : %lu) eoff %lu", rginfo->gen, rginfo->fileid,
                info->min_seqno, info->max_seqno, info->min_gen, info->max_gen,
                info->min_txid, info->max_txid, rginfo->eoff);
    }
}

static void
wal_replay_dump_rgen(struct wal_replay *rep)
{
    struct wal_replay_gen *cur;

    list_for_each_entry(cur, &rep->r_head, rg_link) {
        hse_log(HSE_NOTICE "WAL replay: Gen %lu Seqno (%lu : %lu) Memsz: %lu", cur->rg_gen,
                cur->rg_info.min_seqno, cur->rg_info.max_seqno, cur->rg_bytes);
    }
}
#endif
