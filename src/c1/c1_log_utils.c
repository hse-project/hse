/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_omf_internal.h"

#include <mpool/mpool.h>

static merr_t
c1_log_read(struct c1_log *log, u64 seek, void *data, size_t len)
{
    size_t len_read;
    merr_t err;

    err = mpool_mlog_seek_read(log->c1l_mlh, seek, data, len, &len_read);
    if (ev(err)) {
        if ((merr_errno(err) == ERANGE) && !len_read)
            return merr(ev(ENOENT));

        hse_elog(
            HSE_ERR "%s: mpool_mlog_seek_read failed: "
                    "@@e",
            err,
            __func__);
        return err;
    }

    if (len_read == 0)
        return merr(ev(ENOENT));

    if (len != len_read) {
        if (len_read)
            hse_log(
                HSE_WARNING "c1_log_read len %ld len_read %ld",
                (unsigned long)len,
                (unsigned long)len_read);

        return merr(ev(ENOENT));
    }

    log->c1l_repoffset += seek + len;

    return 0;
}

static merr_t
c1_log_skip_data(struct c1_log *log, u64 skiplen)
{
    merr_t err;
    size_t len_read;

    err = mpool_mlog_seek_read(log->c1l_mlh, skiplen, NULL, 0, &len_read);
    if (ev(err))
        return err;

    assert(skiplen == len_read);

    log->c1l_repoffset += skiplen;

    return err;
}

static merr_t
c1_log_verify_hdr(struct c1_log *log, u16 ver)
{
    char * kvlomf;
    merr_t err;
    u64    mdcoid1;
    u64    mdcoid2;
    u64    c1loid;
    u32    len;

    kvlomf = log->c1l_repbuf;

    err = c1_record_type2len(C1_TYPE_KVLOG, ver, &len);
    if (ev(err))
        return err;

    assert(len <= log->c1l_repbuflen);

    err = c1_log_read(log, 0, kvlomf, len);
    if (ev(err))
        return err;

    mdcoid1 = log->c1l_mdcoid1;
    mdcoid2 = log->c1l_mdcoid2;
    c1loid = log->c1l_oid;

    err = c1_record_unpack(kvlomf, ver, (union c1_record *)log);
    if (ev(err))
        return err;

    if ((mdcoid1 != log->c1l_mdcoid1) || (mdcoid2 != log->c1l_mdcoid2)) {

        hse_log(
            HSE_ERR "%s: MDCOIDs %p-%p %p-%p do not match",
            __func__,
            (void *)mdcoid1,
            (void *)mdcoid2,
            (void *)log->c1l_mdcoid1,
            (void *)log->c1l_mdcoid2);

        return merr(ev(EINVAL));
    }

    if (c1loid != log->c1l_oid) {
        hse_log(
            HSE_ERR "%s: log oid %p-%p does not match with what "
                    "was saved in the log",
            __func__,
            (void *)c1loid,
            (void *)log->c1l_oid);

        return merr(ev(EINVAL));
    }

    return 0;
}

merr_t
c1_log_replay_open(struct c1_log *log, int type, u16 ver)
{
    void * buffer;
    merr_t err;

    buffer = malloc(PAGE_SIZE);
    if (!buffer)
        return merr(ev(ENOMEM));

    err = mpool_mlog_rewind(log->c1l_mlh);
    if (ev(err)) {
        free(buffer);
        return err;
    }

    log->c1l_repbuf = buffer;
    log->c1l_repbuflen = PAGE_SIZE;
    log->c1l_reptype = type;
    log->c1l_repseek = 0;
    log->c1l_repoffset = 0;

    atomic64_set(&log->c1l_kcount, 0);
    atomic64_set(&log->c1l_ckcount, 0);
    atomic64_set(&log->c1l_cvcount, 0);

    err = c1_log_verify_hdr(log, ver);
    if (ev(err)) {
        free(buffer);
        log->c1l_repbuf = NULL;
        log->c1l_repbuflen = 0;
        log->c1l_reptype = C1_REPLAY_INVALID;

        return err;
    }

    return 0;
}

void
c1_log_replay_close(struct c1_log *log, bool destroy)
{
    struct c1_treetxn *txn;
    struct c1_treetxn *tmptxn;
    struct c1_kvb *    kvb;
    struct c1_kvb *    tmpkvb;

    free(log->c1l_repbuf);

    log->c1l_repbuf = NULL;
    log->c1l_repbuflen = 0;
    log->c1l_repoffset = 0;
    log->c1l_reptype = C1_REPLAY_INVALID;

    if (!destroy)
        return;

    list_for_each_entry_safe (txn, tmptxn, &log->c1l_txn_list, c1txn_list) {
        list_del(&txn->c1txn_list);
        free(txn);
    }

    list_for_each_entry_safe (kvb, tmpkvb, &log->c1l_kvb_list, c1kvb_list) {
        list_del(&kvb->c1kvb_list);
        free(kvb->c1kvb_data);
        free(kvb);
    }
}

static merr_t
c1_log_replay_kvb(struct c1_log *log, u64 cningestid, u16 ver)
{
    struct c1_kvb *kvb;

    char * kvbomf;
    void * data;
    merr_t err;

    kvbomf = log->c1l_repbuf;
    log->c1l_repseek = 0;

    kvb = malloc(sizeof(*kvb));
    if (!kvb)
        return merr(ev(ENOMEM));

    err = c1_record_unpack(kvbomf, ver, (union c1_record *)kvb);
    if (ev(err)) {
        free(kvb);
        return err;
    }

    if (!c1_should_replay(cningestid, kvb->c1kvb_ingestid)) {
        c1_log_skip_data(log, kvb->c1kvb_size);
        free(kvb);
        return 0;
    }

    INIT_LIST_HEAD(&kvb->c1kvb_list);
    kvb->c1kvb_log = log;
    kvb->c1kvb_offset = log->c1l_repoffset;

    data = malloc(kvb->c1kvb_size);
    if (!data) {
        free(kvb);
        return merr(ev(ENOMEM));
    }

    err = c1_log_read(log, 0, data, kvb->c1kvb_size);
    if (ev(err)) {
        free(kvb);
        free(data);
        return err;
    }

    kvb->c1kvb_data = data;

    list_add_tail(&kvb->c1kvb_list, &log->c1l_kvb_list);

#ifdef HSE_BUILD_DEBUG
    hse_log(
        HSE_DEBUG "c1 replay kvb seqno %lx gen %x txn %lxkcount %lx "
                "mutation %lx size %lx minseqno %lx maxseqno %lx",
        (unsigned long)kvb->c1kvb_seqno,
        (unsigned int)kvb->c1kvb_gen,
        (unsigned long)kvb->c1kvb_txnid,
        (unsigned long)kvb->c1kvb_keycount,
        (unsigned long)kvb->c1kvb_mutation,
        (unsigned long)kvb->c1kvb_size,
        (unsigned long)kvb->c1kvb_minseqno,
        (unsigned long)kvb->c1kvb_maxseqno);
#endif

    return 0;
}

static merr_t
c1_log_replay_txn(struct c1_log *log, u64 cningestid, u16 ver)
{
    struct c1_treetxn *ttxn;

    char * txnomf;
    merr_t err;

    txnomf = log->c1l_repbuf;
    log->c1l_repseek = 0;

    ttxn = malloc(sizeof(*ttxn));
    if (!ttxn)
        return merr(ev(ENOMEM));

    err = c1_record_unpack(txnomf, ver, (union c1_record *)ttxn);
    if (ev(err)) {
        free(ttxn);
        return err;
    }

    if (ttxn->c1txn_cmd != C1_TYPE_TXN_COMMIT) {
        free(ttxn);

        return 0;
    }

    if (!c1_should_replay(cningestid, ttxn->c1txn_ingestid)) {
        free(ttxn);

        return 0;
    }

    INIT_LIST_HEAD(&ttxn->c1txn_list);

    list_add_tail(&ttxn->c1txn_list, &log->c1l_txn_list);

#ifdef HSE_BUILD_DEBUG
    hse_log(
        HSE_DEBUG "replay txn seqno %lx gen %lx txnid %lx "
                "c1ingestid %lx cmd %x flag %x",
        (unsigned long)ttxn->c1txn_seqno,
        (unsigned long)ttxn->c1txn_gen,
        (unsigned long)ttxn->c1txn_id,
        (unsigned long)ttxn->c1txn_ingestid,
        (unsigned int)ttxn->c1txn_cmd,
        (unsigned int)ttxn->c1txn_flag);
#endif

    return 0;
}

static merr_t
c1_log_replay_metadata(struct c1_log *log, u64 cningestid, u16 ver)
{
    struct c1_kvb kvb;

    merr_t err;
    char * hdromf;
    char * kvbomf;
    u64    seek;
    u64    ckcnt;
    u32    kvbsz;

    err = c1_record_type2len(C1_TYPE_KVB, ver, &kvbsz);
    if (ev(err))
        return err;

    while (1) {
        err = c1_log_read(log, log->c1l_repseek, log->c1l_repbuf, kvbsz);
        if (ev(err))
            break;

        hdromf = log->c1l_repbuf;

        switch (omf_c1_header_type(hdromf)) {
            case C1_TYPE_KVB:
                kvbomf = log->c1l_repbuf;

                err = c1_record_unpack(kvbomf, ver, (union c1_record *)&kvb);
                if (ev(err))
                    return err;

                seek = kvb.c1kvb_size;
                ckcnt = kvb.c1kvb_ckeycount;

                assert(seek > 0);

                log->c1l_repseek = seek;
                atomic64_add(kvb.c1kvb_keycount, &log->c1l_kcount);
                if (ckcnt > atomic64_read(&log->c1l_ckcount))
                    atomic64_set(&log->c1l_ckcount, ckcnt);

                break;

            case C1_TYPE_TXN:
                err = c1_log_replay_txn(log, cningestid, ver);
                break;

            default:
                break;
        }

        if (ev(err))
            break;
    }

    return err;
}

static merr_t
c1_log_replay_kvbundle(struct c1_log *log, u64 cningestid, u16 ver)
{
    merr_t err;
    char * hdromf;
    u32    kvbsz;

    err = c1_record_type2len(C1_TYPE_KVB, ver, &kvbsz);
    if (ev(err))
        return err;

    while (1) {
        err = c1_log_read(log, log->c1l_repseek, log->c1l_repbuf, kvbsz);
        if (ev(err))
            break;

        hdromf = log->c1l_repbuf;

        switch (omf_c1_header_type(hdromf)) {
            case C1_TYPE_KVB:
                err = c1_log_replay_kvb(log, cningestid, ver);
                break;

            case C1_TYPE_TXN:
                continue;

            default:
                err = merr(ev(EBADMSG));
                break;
        }

        if (ev(err))
            break;
    }

    return err;
}

merr_t
c1_log_replay(struct c1_log *log, u64 cningestid, u16 ver)
{
    if (log->c1l_reptype == C1_REPLAY_METADATA)
        return c1_log_replay_metadata(log, cningestid, ver);

    return c1_log_replay_kvbundle(log, cningestid, ver);
}

/*
 * c1log diagnostics functions. Disabling coverage on them.
 */
BullseyeCoverageSaveOff
merr_t
c1_log_diag_replay_open(struct c1_log *log, c1_journal_replay_cb *cb, void *cbarg, u16 ver)
{
    void * buffer;
    merr_t err;
    merr_t err2;

    buffer = malloc(PAGE_SIZE);
    if (ev(!buffer))
        return merr(ENOMEM);

    err = mpool_mlog_rewind(log->c1l_mlh);
    if (ev(err)) {
        free(buffer);
        return err;
    }

    log->c1l_repbuf = buffer;
    log->c1l_repbuflen = PAGE_SIZE;
    log->c1l_reptype = C1_REPLAY_INVALID;
    log->c1l_repseek = 0;
    log->c1l_repoffset = 0;

    atomic64_set(&log->c1l_kcount, 0);
    atomic64_set(&log->c1l_ckcount, 0);
    atomic64_set(&log->c1l_cvcount, 0);

    err = c1_log_verify_hdr(log, ver);
    err2 = cb(cbarg, C1_TYPE_KVLOG, log->c1l_repbuf, (void *)log->c1l_oid);

    if (err || err2) {
        free(buffer);
        log->c1l_repbuf = NULL;
        log->c1l_repbuflen = 0;
        log->c1l_reptype = C1_REPLAY_INVALID;

        if (ev(err))
            return err;

        return ev(err2);
    }

    return 0;
}

merr_t
c1_log_diag_replay(struct c1_log *log, c1_journal_replay_cb *cb, void *cbarg, u16 ver)
{
    struct c1_kvb kvb;

    char * kv;
    char * hdromf;
    merr_t err;
    void * data;
    u64    size;
    u32    kvbsz;

    assert(cb);
    assert(cbarg);
    if (ev(!cb || !cbarg))
        return merr(EINVAL);

    err = c1_log_diag_replay_open(log, cb, cbarg, ver);
    if (ev(err))
        return err;

    err = c1_record_type2len(C1_TYPE_KVB, ver, &kvbsz);
    if (ev(err)) {
        c1_log_replay_close(log, false);
        return err;
    }

    while (1) {
        err = c1_log_read(log, 0, log->c1l_repbuf, kvbsz);
        if (ev(err))
            break;

        hdromf = log->c1l_repbuf;

        if (omf_c1_header_type(hdromf) != C1_TYPE_KVB) {
            err = cb(cbarg, omf_c1_header_type(hdromf), hdromf, NULL);
            if (ev(err))
                break;
            continue;
        }

        kv = log->c1l_repbuf;
        err = c1_record_unpack(kv, ver, (union c1_record *)&kvb);
        if (ev(err))
            return err;

        size = kvb.c1kvb_size;
        data = malloc(size);
        if (!data) {
            err = merr(ev(ENOMEM));
            break;
        }

        err = c1_log_read(log, 0, data, size);
        if (ev(err)) {
            free(data);
            break;
        }

        err = cb(cbarg, C1_TYPE_KVB, hdromf, data);
        free(data);
        if (ev(err))
            break;
    }

    c1_log_replay_close(log, false);

    if (merr_errno(err) == ENOENT)
        err = 0;

    return err;
}
BullseyeCoverageRestore
