/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/workqueue.h>
#include <hse_util/slab.h>
#include <hse_util/bonsai_tree.h>

#include <rbtree/rbtree.h>

#include "wal.h"
#include "wal_replay.h"
#include "wal_file.h"
#include "wal_mdc.h"
#include "wal_omf.h"


struct wal_replay_gen {
    struct list_head       rg_link HSE_ALIGNED(SMP_CACHE_BYTES);
    struct wal_minmax_info rg_info;
    u64                    rg_gen;
    merr_t                 rg_err;

    uint64_t               rg_krcnt;
    uint64_t               rg_maxseqno;

    struct mutex           rg_lock HSE_ALIGNED(SMP_CACHE_BYTES);
    struct rb_root         rg_root;
};

struct wal_replay_work {
    struct work_struct          rw_work;
    struct wal_replay          *rw_rep;
    struct wal_replay_gen      *rw_rgen;
    struct wal_replay_gen_info *rw_rginfo;
};

struct wal_replay {
    struct list_head            r_head;
    struct ikvdb_kvs_hdl       *r_ikvsh;
    struct workqueue_struct    *r_wq;
    struct wal                 *r_wal;
    struct wal_replay_info     *r_info;

    struct kmem_cache          *r_cache;

    uint                        r_cnt;
    struct wal_replay_gen_info *r_ginfo;
};


/* Forward declarations */
#ifndef NDEBUG
static void
wal_replay_dump(struct wal_replay *rep);
#endif


static merr_t
wal_replay_open(struct wal *wal, struct wal_replay_info *rinfo, struct wal_replay **rep_out)
{
    struct wal_replay *rep;
    merr_t err;

    if (!wal || !rep_out)
        return merr(EINVAL);

    rep = calloc(1, sizeof(*rep));
    if (!rep)
        return merr(ENOMEM);

    rep->r_wq = alloc_workqueue("wal_replay_wq", 0, WAL_BUF_MAX);
    if (!rep->r_wq) {
        err =  merr(ENOMEM);
        goto err_exit;
    }

    rep->r_cache = kmem_cache_create("wal-replay", sizeof(struct wal_rec),
                                     alignof(struct wal_rec), 0, NULL);
    if (!rep->r_cache) {
        err = merr(ENOMEM);
        goto err_exit;
    }

    err = ikvdb_wal_replay_open(wal_ikvdb(wal), &rep->r_ikvsh);
    if (err)
        goto err_exit;

    rep->r_wal = wal;
    rep->r_info = rinfo;
    INIT_LIST_HEAD(&rep->r_head);

    *rep_out = rep;

    return 0;

err_exit:
    kmem_cache_destroy(rep->r_cache);
    destroy_workqueue(rep->r_wq);
    free(rep);

    return err;
}

static void
wal_replay_close(struct wal_replay *rep, bool failed)
{
    struct wal_replay_gen *cgen, *ngen;
    struct wal *wal;
    merr_t err;

    if (!rep)
        return;

    wal = rep->r_wal;

    list_for_each_entry_safe(cgen, ngen, &rep->r_head, rg_link) {
        struct rb_root *root = &cgen->rg_root;
        struct wal_rec *cur, *next;

        rbtree_postorder_for_each_entry_safe(cur, next, root, node) {
            kmem_cache_free(rep->r_cache, cur);
        }

        list_del_init(&cgen->rg_link);
        free(cgen);
    }

    wal_fileset_replay_free(wal_fset(wal), failed);

    err = ikvdb_wal_replay_close(wal_ikvdb(wal), rep->r_ikvsh);
    ev(err);

    kmem_cache_destroy(rep->r_cache);
    destroy_workqueue(rep->r_wq);

    free(rep);
}


/*
 * WAL record iterator interfaces
 */

struct wal_rec_iter {
    struct kmem_cache *rcache;
    const char        *buf;
    u64                gen;
    off_t              curoff;
    off_t              rgoff;
    off_t              nrgoff;
    off_t              soff;
    off_t              eoff;
    size_t             size;
    merr_t             err;
    bool               eof;
};

static void
wal_rec_iter_init(struct wal_replay_work *rw, struct wal_rec_iter *iter)
{
    iter->buf = rw->rw_rginfo->buf;
    iter->gen = rw->rw_rgen->rg_gen;
    iter->curoff = iter->nrgoff = iter->rgoff = 0;
    iter->soff = rw->rw_rginfo->soff;
    iter->eoff = rw->rw_rginfo->eoff;
    iter->eof = false;
    iter->rcache = rw->rw_rep->r_cache;
    iter->size = rw->rw_rginfo->size;
    iter->err = 0;
}

bool
wal_rec_iter_eof(struct wal_rec_iter *iter)
{
    return iter->eof;
}

static struct wal_rec *
wal_rec_iter_next(struct wal_rec_iter *iter)
{
    struct wal_rec *rec;
    const char *buf;

next_rec:
    buf = iter->buf;
    buf += iter->curoff;

    if (iter->eof)
        return NULL;

    /* Determine the next record group boundary and validate records */
    if (iter->curoff == iter->nrgoff) {
        off_t recoff = 0;
        off_t curoff = iter->curoff;
        bool valid;

        iter->rgoff = iter->nrgoff;

        /* Determine eorg or stop if the record is invalid */
        while ((valid = wal_rec_is_valid(buf, &recoff, iter->gen)) && !wal_rec_is_eorg(buf)) {
            size_t len = wal_rec_total_len(buf);

            curoff += len;
            buf += len;
            recoff += len;

            if ((iter->eoff != 0 && (curoff + iter->soff >= iter->eoff)) ||
                curoff + iter->soff >= iter->size) {
                valid = false;
                break;
            }
        }

        if (!valid) {
            iter->eof = true;
            return NULL;
        }

        /* Complete rg, update the offsets */
        assert(wal_rec_is_eorg(buf));
        iter->nrgoff = curoff + wal_rec_total_len(buf);

        buf = iter->buf + iter->curoff; /* Reset buf */
        assert(wal_rec_is_borg(buf));
    }

    iter->curoff += wal_rec_total_len(buf);

    /* Validate record group flags */
    if (iter->curoff == iter->nrgoff)
        assert(wal_rec_is_eorg(buf));
    else
        assert(wal_rec_is_morg(buf));

    if (wal_rec_skip(buf))
        goto next_rec;

    rec = kmem_cache_alloc(iter->rcache);
    if (!rec) {
        iter->err = merr(ENOMEM);
        return NULL;
    }

    wal_rec_unpack(buf, rec);

    return rec;
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
    rgen->rg_err = 0;
    rgen->rg_krcnt = 0;
    rgen->rg_maxseqno = 0;
}

static void
wal_replay_gen_update(struct wal_replay_gen *rgen, struct wal_replay_gen_info *rginfo)
{
    struct wal_minmax_info *info;

    if (!rgen || !rginfo->info_valid)
        return;

    info = &rgen->rg_info;
    info->min_seqno = min_t(u64, info->min_seqno, rginfo->info.min_seqno);
    info->max_seqno = max_t(u64, info->max_seqno, rginfo->info.max_seqno);
    info->min_gen = min_t(u64, info->min_gen, rginfo->info.min_gen);
    info->max_gen = max_t(u64, info->max_gen, rginfo->info.max_gen);
    info->min_txid = min_t(u64, info->min_txid, rginfo->info.min_txid);
    info->max_txid = max_t(u64, info->max_txid, rginfo->info.max_txid);
}

static struct wal_replay_gen *
wal_replay_gen_get(struct wal_replay *rep, u64 gen)
{
    struct wal_replay_gen *cur;

    list_for_each_entry(cur, &rep->r_head, rg_link) {
        if (cur->rg_gen == gen)
            return cur;
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
            err = ikvdb_wal_replay_pdel(ikvdb, ikvsh, rec->cnid, rec->seqno, kt);
            break;

          default:
            err = merr(EINVAL);
            break;
        }

        if (err)
            goto err_exit;

        rgen->rg_maxseqno = max_t(u64, rgen->rg_maxseqno, rec->seqno);

        rb_erase(&rec->node, root);
        kmem_cache_free(rep->r_cache, rec);
        rgen->rg_krcnt++;
    }

    return 0;

err_exit:
    do {
        struct wal_rec *cur, *next;

        rbtree_postorder_for_each_entry_safe(cur, next, root, node) {
            kmem_cache_free(rep->r_cache, cur);
        }
    } while (0);

    return err;
}


/*
 * General WAL replay interfaces
 */

static merr_t
wal_replay_core(struct wal_replay *rep)
{
    struct wal_replay_gen *cur, *next;
    struct ikvdb *ikvdb;
    uint flags;
    u64 maxseqno = 0;

    if (!rep)
        return merr(EINVAL);

    ikvdb = wal_ikvdb(rep->r_wal);
    flags = HSE_BTF_MANAGED;

    ikvdb_wal_replay_set(ikvdb);

    list_for_each_entry_safe(cur, next, &rep->r_head, rg_link) {
        merr_t err;

        ikvdb_wal_replay_gen_set(ikvdb, cur->rg_gen);

        err = wal_replay_gen_impl(rep, cur, flags);
        if (err) {
            ikvdb_wal_replay_unset(ikvdb);
            return err;
        }

        if (cur->rg_krcnt && (cur != list_last_entry(&rep->r_head, typeof(*cur), rg_link))) {
            err = ikvdb_sync(ikvdb, HSE_FLAG_SYNC_ASYNC);
            if (err) {
                ikvdb_wal_replay_unset(ikvdb);
                return err;
            }
        }

        maxseqno = max_t(u64, maxseqno, cur->rg_maxseqno);

        hse_log(HSE_NOTICE "WAL replay: gen %lu, maxseqno %lu replayed %lu keys",
                cur->rg_gen, maxseqno, cur->rg_krcnt);

        list_del_init(&cur->rg_link);
        free(cur);
    }

    ikvdb_wal_replay_seqno_set(ikvdb, maxseqno);

    ikvdb_wal_replay_unset(ikvdb);

    return ikvdb_sync(ikvdb, 0);
}

static merr_t
wal_replay_rb_insert(struct wal_replay_gen *rgen, struct wal_rec *rec)
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
    u64                         nrecs = 0;
    merr_t                      err;

    rw = container_of(work, struct wal_replay_work, rw_work);

    rginfo = rw->rw_rginfo;
    rgen = rw->rw_rgen;
    rep = rw->rw_rep;

    wal_rec_iter_init(rw, &iter);

    while ((rec = wal_rec_iter_next(&iter))) {
        struct wal_replay_gen *trgen = rgen;
        u64 gen = rec->hdr.gen;
        u64 seqno = rec->seqno;

        if (seqno <= rep->r_info->seqno) {
            kmem_cache_free(rep->r_cache, rec);
            continue; /* ignore this rec */
        }

        if (HSE_UNLIKELY(gen != trgen->rg_gen)) {
            trgen = wal_replay_gen_get(rep, gen);
        } else {
            assert((!rginfo->info_valid) ||
                   ((gen >= rginfo->info.min_gen && gen <= rginfo->info.max_gen) &&
                   (seqno >= rginfo->info.min_seqno && seqno <= rginfo->info.max_seqno)));
        }
        assert(gen <= trgen->rg_gen);

        mutex_lock(&trgen->rg_lock);
        err = wal_replay_rb_insert(trgen, rec);
        mutex_unlock(&trgen->rg_lock);
        if (err) {
            trgen->rg_err = err;
            break;
        }

        nrecs++;
    }

    if (iter.err && rgen->rg_err == 0)
        rgen->rg_err = iter.err;

    if (rgen->rg_err)
        return;

    hse_log(HSE_NOTICE "%s: gen %lu fileid %d nrecs %lu",
            __func__, rginfo->gen, rginfo->fileid, nrecs);

    assert(wal_rec_iter_eof(&iter));
}

static merr_t
wal_replay_prepare(struct wal_replay *rep)
{
    struct wal_replay_work *work;
    struct wal_replay_gen *rgen;
    u64 prev_gen = 0;
    int i;

    work = calloc(rep->r_cnt, sizeof(*work));
    if (!work)
        return merr(ENOMEM);

    for (i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo;

        rginfo = rep->r_ginfo + i;

        if (prev_gen != rginfo->gen) {
            rgen = wal_replay_gen_get(rep, rginfo->gen);
            prev_gen = rginfo->gen;
        }

        INIT_WORK(&work[i].rw_work, wal_replay_worker);
        work[i].rw_rep = rep;
        work[i].rw_rgen = rgen;
        work[i].rw_rginfo = rginfo;

        queue_work(rep->r_wq, &work[i].rw_work);
    }

    flush_workqueue(rep->r_wq);

    for (i = 0; i < rep->r_cnt; i++) {
        if (work[i].rw_rgen->rg_err)
            return work[i].rw_rgen->rg_err;
    }

    free(work);

    return 0;
}

static merr_t
wal_replay_consolidate(struct wal_replay *rep)
{
    struct wal_replay_gen *prev_rgen = NULL;
    merr_t err = 0;
    u64 prev_gen = 0;
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
        struct wal_replay_gen *cur, *next;

        list_for_each_entry_safe(cur, next, &rep->r_head, rg_link) {
            list_del_init(&cur->rg_link);
            free(cur);
        }
    }

    return err;
}

merr_t
wal_replay(struct wal *wal, struct wal_replay_info *rinfo)
{
    struct wal_replay *rep = NULL;
    merr_t err = 0;

    err = wal_mdc_replay(wal_mdc(wal), wal);
    if (err)
        return err;

    if (wal_is_rdonly(wal) || wal_is_clean(wal))
        return 0;

    err = wal_replay_open(wal, rinfo, &rep);
    if (err)
        return err;

    err = wal_fileset_replay(wal_fset(wal), rinfo, &rep->r_cnt, &rep->r_ginfo);
    if (err)
        goto exit;

#ifndef NDEBUG
    wal_replay_dump(rep);
#endif

    err = wal_replay_consolidate(rep);
    if (err)
        goto exit;

    err = wal_replay_prepare(rep);
    if (err)
        goto exit;

    err = wal_replay_core(rep);
    if (err)
        goto exit;

exit:
    wal_replay_close(rep, !!err);

    return err;
}

#ifndef NDEBUG
static void
wal_replay_dump(struct wal_replay *rep)
{
    hse_log(HSE_NOTICE "Replay entry count: %u", rep->r_cnt);

    for (int i = 0; i < rep->r_cnt; i++) {
        struct wal_replay_gen_info *rginfo;
        struct wal_minmax_info *info;

        hse_log(HSE_NOTICE "Entry %u", i);

        rginfo = rep->r_ginfo + i;
        info = &rginfo->info;

        hse_log(HSE_NOTICE "Gen %lu Fileid %u Seqno (%lu : %lu) gen (%lu : %lu) "
                "txhorizon (%lu : %lu)", rginfo->gen, rginfo->fileid,
                info->min_seqno, info->max_seqno, info->min_gen, info->max_gen,
                info->min_txid, info->max_txid);
    }
}
#endif
