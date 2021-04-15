/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_kvdb_log
#include <hse_util/platform.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/event_counter.h>
#include <hse_util/table.h>
#include <hse_util/string.h>

#include <hse/hse.h>

#include "kvdb_omf.h"

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/limits.h>

#include <mpool/mpool.h>

#include "kvdb_log.h"

void
kvdb_log_mdx_dump(char *dir, union kvdb_mdu *mdp, size_t sz)
{
    switch (mdp->h.mdh_type) {
        case KVDB_LOG_TYPE_VERSION:
            hse_log(
                HSE_DEBUG "%s,%s(%lu): ver %d magic %x captgt %lu",
                __func__,
                dir,
                (ulong)sz,
                mdp->v.mdv_version,
                mdp->v.mdv_magic,
                (ulong)mdp->v.mdv_captgt);
            break;
        case KVDB_LOG_TYPE_MDC:
            hse_log(
                HSE_DEBUG "%s,%s(%lu): mdc disp %d id %d oids "
                          "(x%lx, x%lx)",
                __func__,
                dir,
                (ulong)sz,
                mdp->c.mdc_disp,
                mdp->c.mdc_id,
                (ulong)mdp->c.mdc_new_oid1,
                (ulong)mdp->c.mdc_new_oid2);
            break;
        default:
            hse_log(
                HSE_ERR "%s,%s(%lu): unknown record type %d",
                __func__,
                dir,
                (ulong)sz,
                mdp->h.mdh_type);
    }
}

/* PRIVATE */
size_t
kvdb_log_mdx_to_omf(struct kvdb_log_hdr2_omf *omf, union kvdb_mdu *mdp)
{
    size_t sz;

    switch (mdp->h.mdh_type) {
        case KVDB_LOG_TYPE_VERSION:
            sz = sizeof(struct kvdb_log_ver4_omf);
            memset(omf, 0, sz);
            omf_set_hdr_len(omf, KVDB_LOG_OMF_LEN(sz));
            omf_set_ver_magic((void *)omf, mdp->v.mdv_magic);
            omf_set_ver_version((void *)omf, mdp->v.mdv_version);
            omf_set_ver_captgt((void *)omf, mdp->v.mdv_captgt);
            break;
        case KVDB_LOG_TYPE_MDC:
            sz = sizeof(struct kvdb_log_mdc_omf);
            memset(omf, 0, sz);
            omf_set_hdr_len(omf, KVDB_LOG_OMF_LEN(sz));
            omf_set_mdc_disp((void *)omf, mdp->c.mdc_disp);
            omf_set_mdc_id((void *)omf, mdp->c.mdc_id);
            omf_set_mdc_new_oid1((void *)omf, mdp->c.mdc_new_oid1);
            omf_set_mdc_new_oid2((void *)omf, mdp->c.mdc_new_oid2);
            break;
        default:
            return 0;
    }

    omf_set_hdr_type(omf, mdp->h.mdh_type);

    kvdb_log_mdx_dump("write", mdp, sz);

    return sz;
}

/* PRIVATE */
merr_t
kvdb_log_disp_set(union kvdb_mdu *mdp, enum kvdb_log_disp disp)
{
    if (mdp->h.mdh_type == KVDB_LOG_TYPE_MDC) {
        mdp->c.mdc_disp = disp;
        return 0;
    }

    return 0;
}

/* PRIVATE */
enum kvdb_log_disp
kvdb_log_disp(const union kvdb_mdu *mdp)
{
    if (mdp->h.mdh_type == KVDB_LOG_TYPE_MDC)
        return mdp->c.mdc_disp;

    return 0;
}

/* PRIVATE */
u64
kvdb_log_id(const union kvdb_mdu *mdp)
{
    if (mdp->h.mdh_type == KVDB_LOG_TYPE_MDC)
        return (u64)mdp->c.mdc_id;

    return 0;
}

/* PRIVATE */
bool
kvdb_log_finished(union kvdb_mdu *mdp)
{
    enum kvdb_log_disp disp = kvdb_log_disp(mdp);

    if (disp == KVDB_LOG_DISP_MAKE_DONE(disp))
        return true;
    return false;
}

/* PRIVATE */
int
kvdb_log_cmp(const void *a, const void *b)
{
    const union kvdb_mdu *aa = a;
    const union kvdb_mdu *bb = b;
    u64                   aid, bid;

    if (aa->h.mdh_type != bb->h.mdh_type)
        return aa->h.mdh_type - bb->h.mdh_type;

    /* type is equal */
    aid = kvdb_log_id(aa);
    bid = kvdb_log_id(bb);

    if (aid != bid)
        return aid - bid;

    /* id is equal */

    if (aa->h.mdh_serial != bb->h.mdh_serial)
        return aa->h.mdh_serial - bb->h.mdh_serial;

    return 0;
}

/* PRIVATE */
merr_t
kvdb_log_mdc_keep(struct kvdb_log *log, union kvdb_mdu *mdp)
{
    if (mdp->c.mdc_id <= KVDB_LOG_MDC_ID_MAX) {
        if (mdp->c.mdc_id == KVDB_LOG_MDC_ID_CNDB) {
            log->kl_cndb_oid1 = mdp->c.mdc_new_oid1;
            log->kl_cndb_oid2 = mdp->c.mdc_new_oid2;
        }
        return 0;
    } else {
        return merr(ev(EPROTO));
    }
}

/* PRIVATE */
merr_t
kvdb_log_keep(struct kvdb_log *log, union kvdb_mdu *mdp)
{
    merr_t err;

    /* MDC drop is not yet implemented,  */
    if (kvdb_log_disp(mdp) == KVDB_LOG_DISP_DESTROY_DONE)
        return merr(ev(EOPNOTSUPP));

    /* MDC replace is not yet implemented */
    if (kvdb_log_disp(mdp) == KVDB_LOG_DISP_REPLACE_DONE)
        return merr(ev(EOPNOTSUPP));

    if (mdp->h.mdh_type == KVDB_LOG_TYPE_MDC)
        err = ev(kvdb_log_mdc_keep(log, mdp));
    else
        return merr(ev(EPROTO));

    return err;
}

/* PRIVATE */
merr_t
kvdb_log_rollback_oids(struct kvdb_log *log, union kvdb_mdu *mdp)
{
    merr_t err;

    err = mpool_mdc_delete(log->kl_ds, mdp->c.mdc_new_oid1, mdp->c.mdc_new_oid2);

    /* If the mdc is already destroyed, report success */
    if (merr_errno(err) == ENOENT)
        return 0;

    return ev(err);
}

/* PRIVATE */
merr_t
kvdb_log_rollback(struct kvdb_log *log, union kvdb_mdu *mdp)
{
    /* MDC drop is not yet implemented,  */
    if (kvdb_log_disp(mdp) == KVDB_LOG_DISP_DESTROY)
        return merr(ev(EOPNOTSUPP));

    /* MDC replace is not yet implemented */
    if (kvdb_log_disp(mdp) == KVDB_LOG_DISP_REPLACE)
        return merr(ev(EOPNOTSUPP));

    if (mdp->h.mdh_type == KVDB_LOG_TYPE_MDC && mdp->c.mdc_id <= KVDB_LOG_MDC_ID_MAX)
        return ev(kvdb_log_rollback_oids(log, mdp));

    return merr(ev(EPROTO));
}

merr_t
kvdb_log_rollforward(struct kvdb_log *log, union kvdb_mdu *mdp)
{
    /* A roll-forward for kvdb_log is actually a rollback of some OIDs */
    return ev(kvdb_log_rollback(log, mdp));
}

merr_t
kvdb_log_omf_to_mdx(union kvdb_mdu *mdp, struct kvdb_log_hdr2_omf *omf, u32 serial)
{
    size_t sz = omf_hdr_len(omf) + sizeof(*omf);

    memset(mdp, 0, sizeof(*mdp));
    mdp->h.mdh_type = omf_hdr_type(omf);
    mdp->h.mdh_serial = serial;

    switch (mdp->h.mdh_type) {
        case KVDB_LOG_TYPE_VERSION:
            mdp->v.mdv_magic = omf_ver_magic((void *)omf);
            mdp->v.mdv_version = omf_ver_version((void *)omf);
            mdp->v.mdv_captgt = omf_ver_captgt((void *)omf);
            break;
        case KVDB_LOG_TYPE_MDC:
            mdp->c.mdc_disp = omf_mdc_disp((void *)omf);
            mdp->c.mdc_id = omf_mdc_id((void *)omf);
            mdp->c.mdc_new_oid1 = omf_mdc_new_oid1((void *)omf);
            mdp->c.mdc_new_oid2 = omf_mdc_new_oid2((void *)omf);
            break;
        default:
            return merr(ev(EPROTO));
    }

    kvdb_log_mdx_dump("read", mdp, sz);
    return 0;
}

merr_t
kvdb_log_replay(
    struct kvdb_log *log,
    u64 *            cndblog_oid1,
    u64 *            cndblog_oid2)
{
    merr_t err;
    size_t len;

    *cndblog_oid1 = 0;
    *cndblog_oid2 = 0;

    err = mpool_mdc_rewind(log->kl_mdc);
    if (ev(err))
        return err;

    log->kl_serial = 0;

    err = mpool_mdc_read(log->kl_mdc, log->kl_buf, sizeof(log->kl_buf), &len);
    if (ev(err))
        return err;

    if (len == 0)
        return merr(ev(ENODATA));

    if (omf_hdr_type((void *)log->kl_buf) != KVDB_LOG_TYPE_VERSION)
        return merr(ev(EPROTO));

    if (omf_ver_magic((void *)log->kl_buf) != KVDB_LOG_MAGIC)
        return merr(ev(EUNATCH));

    if (omf_ver_version((void *)log->kl_buf) != KVDB_LOG_VERSION)
        return merr(ev(EPROTONOSUPPORT));

    log->kl_captgt = omf_ver_captgt((void *)log->kl_buf);
    log->kl_highwater = KVDB_LOG_HIGH_WATER(log);

    while (!err) {
        union kvdb_mdu *mdp;
        size_t          len;

        err = mpool_mdc_read(log->kl_mdc, log->kl_buf, sizeof(log->kl_buf), &len);
        if (len == 0 || ev(err))
            break;

        mdp = table_append(log->kl_work);
        if (!mdp)
            goto out;

        err = kvdb_log_omf_to_mdx(mdp, (void *)log->kl_buf, log->kl_serial++);
        if (ev(err))
            goto out;
    }

    if (ev(err && merr_errno(err) != ENOMSG))
        return err;

    err = kvdb_log_compact(log);
    if (ev(err))
        goto out;

    /* [HSE_REVISIT] attempt to re-make cndb mdc */
    if (!log->kl_cndb_oid1 || !log->kl_cndb_oid2)
        err = merr(ev(EIDRM));

    /* [HSE_REVISIT] WAL is optional for now */

    if (err)
        hse_elog(
            HSE_ERR "%s: failed to read OIDs 0x%lx 0x%lx: @@e",
            err,
            __func__,
            (ulong)log->kl_cndb_oid1,
            (ulong)log->kl_cndb_oid2);

out:
    if (err) {
        hse_elog(HSE_ERR "Error reading kvdb MDC at offset %lu: @@e", err, (ulong)log->kl_serial);
    } else {
        *cndblog_oid1 = log->kl_cndb_oid1;
        *cndblog_oid2 = log->kl_cndb_oid2;

        /* [HSE_REVISIT] this keeps the log optimally small, but it isn't
         * strictly necessary.  To remove it, we must log the following
         * disposition records in kvdb_log_compact():
         *
         *     ABORT, ABORT_DONE, DESTROY_DONE
         *
         * Doing so might induce a rollover.  To keep it simple, we
         * rollover-on-open.
         */
        if (!log->kl_rdonly)
            err = ev(kvdb_log_rollover(log));
    }

    return err;
}

merr_t
kvdb_log_make(struct kvdb_log *log, u64 captgt)
{
    merr_t                   err;
    struct kvdb_log_ver4_omf ver = {};

    if (!log)
        return merr(ev(EINVAL));

    omf_set_hdr_type(&ver.hdr, KVDB_LOG_TYPE_VERSION);
    omf_set_hdr_len(&ver.hdr, KVDB_LOG_OMF_LEN(sizeof(ver)));
    omf_set_ver_version(&ver, KVDB_LOG_VERSION);
    omf_set_ver_magic(&ver, KVDB_LOG_MAGIC);
    omf_set_ver_captgt(&ver, captgt);

    err = mpool_mdc_append(log->kl_mdc, &ver, sizeof(ver), true);
    if (ev(err))
        return err;

    log->kl_captgt = captgt;
    log->kl_highwater = KVDB_LOG_HIGH_WATER(log);

    return 0;
}

merr_t
kvdb_log_open(struct mpool *ds, struct kvdb_log **handle, int mode)
{
    struct kvdb_log *log;
    merr_t           err;
    u64              oid1, oid2;

    assert(sizeof((*handle)->kl_buf) >= sizeof(union kvdb_mdu));

    *handle = NULL;

    log = calloc(1, sizeof(*log));
    if (!log)
        return merr(ev(ENOMEM));

    log->kl_work = table_create(KVDB_LOG_TABLE_DEFAULT, sizeof(union kvdb_mdu), false);
    if (!log->kl_work) {
        free(log);
        return merr(ev(ENOMEM));
    }

    log->kl_work_old = table_create(KVDB_LOG_TABLE_DEFAULT, sizeof(union kvdb_mdu), false);
    if (!log->kl_work_old) {
        table_destroy(log->kl_work);
        free(log);
        return merr(ev(ENOMEM));
    }

    log->kl_ds = ds;
    log->kl_rdonly = (mode == O_RDONLY);

    err = mpool_mdc_rootid_get(ds, &oid1, &oid2);
    if (ev(err))
        goto err_exit;

    err = mpool_mdc_open(log->kl_ds, oid1, oid2, &log->kl_mdc);
    if (ev(err))
        goto err_exit;

    *handle = log;

    return 0;

err_exit:
    table_destroy(log->kl_work_old);
    table_destroy(log->kl_work);
    free(log);

    return err;
}

merr_t
kvdb_log_close(struct kvdb_log *log)
{
    merr_t err = 0;

    if (!log)
        return 0;

    table_destroy(log->kl_work_old);
    table_destroy(log->kl_work);

    err = mpool_mdc_close(log->kl_mdc);
    if (ev(err))
        return err;

    free(log);

    return 0;
}

merr_t
kvdb_log_usage(struct kvdb_log *log, uint64_t *allocated, uint64_t *used)
{
    return mpool_mdc_usage(log->kl_mdc, allocated, used);
}

/* PRIVATE */
merr_t
kvdb_log_rollover(struct kvdb_log *log)
{
    int             c, i;
    size_t          sz;
    merr_t          err;
    struct table *  tab;
    union kvdb_mdu *tx, *dst;
    union kvdb_mdu  mdu;

    c = table_len(log->kl_work);
    hse_log(HSE_DEBUG "%s: commencing %u", __func__, c);

    tab = log->kl_work_old;
    table_reset(tab);

    for (i = 0; i < c; i++) {
        tx = table_at(log->kl_work, i);
        if (kvdb_log_finished(tx))
            continue;

        dst = table_append_object(tab, tx);
        if (ev(!dst)) {
            err = merr(ENOMEM);
            goto out;
        }
    }

    err = mpool_mdc_cstart(log->kl_mdc);
    if (ev(err))
        goto out;

    sz = sizeof(struct kvdb_log_ver4_omf);
    memset(&mdu, 0, sizeof(mdu));
    memset(log->kl_buf, 0, sz);
    mdu.h.mdh_type = KVDB_LOG_TYPE_VERSION;
    mdu.v.mdv_magic = KVDB_LOG_MAGIC;
    mdu.v.mdv_version = KVDB_LOG_VERSION;
    mdu.v.mdv_captgt = log->kl_captgt;
    kvdb_log_mdx_to_omf((void *)log->kl_buf, &mdu);
    err = mpool_mdc_append(log->kl_mdc, log->kl_buf, sz, false);
    if (ev(err))
        goto out;

    if (log->kl_cndb_oid1 && log->kl_cndb_oid2) {
        sz = sizeof(struct kvdb_log_mdc_omf);
        memset(&mdu, 0, sizeof(mdu));
        memset(log->kl_buf, 0, sz);
        mdu.h.mdh_type = KVDB_LOG_TYPE_MDC;
        mdu.c.mdc_disp = KVDB_LOG_DISP_CREATE_DONE;
        mdu.c.mdc_id = KVDB_LOG_MDC_ID_CNDB;
        mdu.c.mdc_new_oid1 = log->kl_cndb_oid1;
        mdu.c.mdc_new_oid2 = log->kl_cndb_oid2;
        kvdb_log_mdx_to_omf((void *)log->kl_buf, &mdu);
        err = mpool_mdc_append(log->kl_mdc, log->kl_buf, sz, false);
        if (ev(err))
            goto out;
    }

    c = table_len(tab);
    for (i = 0; i < c; i++) {
        tx = table_at(tab, i);
        memset(log->kl_buf, 0, sizeof(log->kl_buf));
        sz = kvdb_log_mdx_to_omf((void *)log->kl_buf, tx);
        err = mpool_mdc_append(log->kl_mdc, log->kl_buf, sz, false);
        if (ev(err))
            goto out;
    }

    err = ev(mpool_mdc_cend(log->kl_mdc));

out:
    if (err) {
        log->kl_rdonly = true;
    } else {
        struct table *tmp = log->kl_work;

        log->kl_work = tab;
        log->kl_work_old = tmp;
    }

    hse_elog(HSE_DEBUG "%s: finished: @@e", err, __func__);

    return err;
}

/* kvdb_log_compact() - process metadata
 *
 * Sort on type, label, and serial such that records matching the tuple
 * (type, id) are grouped together, in order of increasing serial number.
 *
 * For each group with matching tuples, it is sufficient to process only the
 * last record. Here is an example.  The serial number indicates the position in
 * the log. Serial 16 demonstrates a missing DESTROY_DONE record.
 *
 *    CFTYPE        ID         SERIAL     DISPOSITION    ALGORITHM KEEPS
 *    -----------------------------------------------------------------------
 *    MDC           1          2          CREATE
 *    MDC           1          3          CREATE_DONE
 *    MDC           1          8          DESTROY
 *    MDC           1          9          DESTROY_DONE
 *    MDC           1          10         CREATE
 *    MDC           1          11         CREATE_DONE    THIS RECORD
 *    MDC           2          6          CREATE
 *    MDC           2          7          CREATE_DONE
 *    MDC           2          16         DESTROY        THIS RECORD, KL_WORK
 *    MDC           3          4          CREATE
 *    MDC           3          5          CREATE_DONE    THIS RECORD
 *    MDC           4          12         CREATE
 *    MDC           4          13         CREATE_DONE
 *    MDC           4          14         DESTROY
 *    MDC           4          15         DESTROY_DONE   NO RECORD
 *    MDC           5          17         CREATE
 *    MDC           5          18         ABORT          THIS RECORD, KL_WORK
 *
 */
/* PRIVATE */
merr_t
kvdb_log_compact(struct kvdb_log *log)
{
    union kvdb_mdu *cur;
    union kvdb_mdu *prev = NULL;
    int             workc, i;
    merr_t          err;

    workc = table_len(log->kl_work);
    if (workc < 1)
        return 0;

    hse_log(HSE_DEBUG "%s: commencing, %d records", __func__, workc);

    table_sort(log->kl_work, kvdb_log_cmp);
    err = merr(EINVAL);

    /* iterate from last to first, processing records as described above */
    for (i = workc - 1; i >= 0; i--) {
        cur = table_at(log->kl_work, i);
        if (prev && cur->h.mdh_type == prev->h.mdh_type && kvdb_log_id(cur) == kvdb_log_id(prev))
            continue;

        switch (kvdb_log_disp(cur)) {
            case KVDB_LOG_DISP_CREATE_DONE:
            case KVDB_LOG_DISP_REPLACE_DONE:
                err = ev(kvdb_log_keep(log, cur));
                break;
            case KVDB_LOG_DISP_CREATE:
            case KVDB_LOG_DISP_REPLACE:
                err = ev(kvdb_log_rollback(log, cur));
                break;
            case KVDB_LOG_DISP_DESTROY:
            case KVDB_LOG_DISP_ABORT:
                err = ev(kvdb_log_rollforward(log, cur));
                break;
            case KVDB_LOG_DISP_ABORT_DONE:
            case KVDB_LOG_DISP_DESTROY_DONE:
                /* Discard */
                break;
            default:
                err = merr(ev(EBADRQC));
                break;
        }

        if (ev(err))
            break;

        prev = cur;
    }

    if (!err)
        table_reset(log->kl_work);

    hse_elog(HSE_DEBUG "%s: finished: @@e", err, __func__);

    return err;
}

/* PRIVATE */
merr_t
kvdb_log_journal(struct kvdb_log *log, void *buf, size_t sz)
{
    merr_t err;
    size_t usage = 0;

    if (log->kl_rdonly)
        return merr(ev(EROFS));

    sz += sizeof(struct kvdb_log_hdr2_omf);

    err = mpool_mdc_usage(log->kl_mdc, NULL, &usage);
    if (ev(err))
        goto out;

    if ((usage + sz) > log->kl_highwater) {
        err = kvdb_log_rollover(log);
        if (ev(err))
            goto out;

        err = mpool_mdc_usage(log->kl_mdc, NULL, &usage);
        if (ev(err))
            goto out;

        if ((usage + sz) > log->kl_captgt) {
            err = merr(ev(ENOSPC));
            hse_elog(
                HSE_ERR "%s: MDC full(%lu+%lu)/%lu: @@e",
                err,
                __func__,
                (ulong)usage,
                (ulong)sz,
                (ulong)log->kl_captgt);
            goto out;
        }

        if ((usage + sz) > log->kl_highwater)
            hse_log(HSE_ERR "%s: compacted MDC above high water", __func__);
    }

    err = mpool_mdc_append(log->kl_mdc, buf, sz, true);
    if (ev(err))
        hse_elog(HSE_ERR "%s: cannot append MDC: @@e", err, __func__);

out:
    if (err)
        log->kl_rdonly = true;

    return err;
}

merr_t
kvdb_log_mdc_create(
    struct kvdb_log *    log,
    enum kvdb_log_mdc_id mdcid,
    u64                  oid1,
    u64                  oid2,
    struct kvdb_log_tx **tx)
{
    merr_t          err;
    union kvdb_mdu *mdp;

    *tx = NULL;
    mdp = table_append(log->kl_work);
    if (!mdp)
        return merr(ev(ENOMEM));

    mdp->h.mdh_type = KVDB_LOG_TYPE_MDC;
    mdp->c.mdc_disp = KVDB_LOG_DISP_CREATE;
    mdp->c.mdc_id = mdcid;
    mdp->c.mdc_new_oid1 = oid1;
    mdp->c.mdc_new_oid2 = oid2;

    kvdb_log_mdx_to_omf((void *)log->kl_buf, mdp);

    err = kvdb_log_journal(log, log->kl_buf, omf_hdr_len((void *)log->kl_buf));
    if (ev(err))
        table_prune(log->kl_work);
    else
        *tx = (struct kvdb_log_tx *)mdp;

    return err;
}

merr_t
kvdb_log_abort(struct kvdb_log *log, struct kvdb_log_tx *tx)
{
    union kvdb_mdu *mdp = (union kvdb_mdu *)tx;
    merr_t          err;

    err = kvdb_log_disp_set(mdp, KVDB_LOG_DISP_ABORT);
    if (ev(err))
        return err;

    kvdb_log_mdx_to_omf((void *)log->kl_buf, mdp);

    err = kvdb_log_journal(log, log->kl_buf, omf_hdr_len((void *)log->kl_buf));

    if (ev(err))
        return err;

    /* this abort rolls-forward now */
    err = kvdb_log_rollforward(log, mdp);
    if (ev(err))
        return err;

    err = kvdb_log_disp_set(mdp, KVDB_LOG_DISP_ABORT_DONE);
    if (ev(err))
        return err;

    kvdb_log_mdx_to_omf((void *)log->kl_buf, mdp);

    err = kvdb_log_journal(log, log->kl_buf, omf_hdr_len((void *)log->kl_buf));

    /* If we couldn't log the ABORT_DONE, we retain this item
     * for next rollover and report error.
     */
    if (ev(err))
        kvdb_log_disp_set(mdp, KVDB_LOG_DISP_ABORT);

    return err;
}

merr_t
kvdb_log_done(struct kvdb_log *log, struct kvdb_log_tx *tx)
{
    union kvdb_mdu *   mdp = (union kvdb_mdu *)tx;
    enum kvdb_log_disp disp;
    merr_t             err;

    disp = KVDB_LOG_DISP_MAKE_DONE(kvdb_log_disp(mdp));

    err = kvdb_log_disp_set(mdp, disp);
    if (ev(err))
        return err;

    kvdb_log_mdx_to_omf((void *)log->kl_buf, mdp);

    err = kvdb_log_journal(log, log->kl_buf, omf_hdr_len((void *)log->kl_buf));

    /* Either 1) adopt this mdc or
     *        2) retain a work item.
     */
    if (ev(err))
        kvdb_log_disp_set(mdp, KVDB_LOG_DISP_MAKE_UNDONE(1));
    else
        err = ev(kvdb_log_keep(log, mdp));

    return err;
}

#if HSE_MOCKING
#include "kvdb_log_ut_impl.i"
#endif /* HSE_MOCKING */
