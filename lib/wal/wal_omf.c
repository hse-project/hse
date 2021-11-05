/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c.h>
#include <hse_util/platform.h>
#include <hse_util/page.h>

#include <hse_ikvdb/wal.h>
#include <hse_ikvdb/tuple.h>

#include "wal_omf.h"
#include "wal_replay.h"

void
wal_rechdr_pack(enum wal_rec_type rtype, uint64_t rid, size_t tlen, uint64_t gen, void *outbuf)
{
    struct wal_rechdr_omf *rhomf = outbuf;

    atomic_set((atomic64_t *)&rhomf->rh_off, 0);
    omf_set_rh_flags(rhomf, WAL_FLAGS_MORG);
    omf_set_rh_gen(rhomf, gen);
    omf_set_rh_type(rhomf, rtype);
    omf_set_rh_len(rhomf, tlen - wal_rechdr_len()); /* exclude record hdr */
    omf_set_rh_rid(rhomf, rid);
    omf_set_rh_rsvd(rhomf, 0);
}

uint32_t
wal_rechdr_len(void)
{
    return sizeof(struct wal_rechdr_omf);
}

void
wal_rechdr_crc_pack(char *recbuf, size_t len)
{
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;
    uint32_t crc;
    uint32_t ignore = offsetof(struct wal_rechdr_omf, rh_cksum) + sizeof(rhomf->rh_cksum);

    crc = crc32c(0, recbuf + ignore, len - ignore);
    omf_set_rh_cksum(rhomf, crc);
}

void
wal_rec_pack(
    enum wal_op op,
    uint64_t    cnid,
    uint64_t    txid,
    uint32_t    klen,
    size_t      vxlen,
    void       *outbuf)
{
    struct wal_rec_omf *romf = outbuf;

    omf_set_r_op(romf, op);
    omf_set_r_klen(romf, klen);
    omf_set_r_cnid(romf, cnid);
    omf_set_r_txid(romf, txid);
    omf_set_r_seqno(romf, 0);
    omf_set_r_vxlen(romf, vxlen);
}

uint32_t
wal_reclen(void)
{
    return sizeof(struct wal_rec_omf);
}

void
wal_rec_finish(struct wal_record *rec, uint64_t seqno, uint64_t gen)
{
    char *recbuf = rec->recbuf;
    struct wal_rec_omf *romf = (struct wal_rec_omf *)recbuf;
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;

    omf_set_rh_gen(rhomf, gen);
    omf_set_r_seqno(romf, seqno);
    wal_rechdr_crc_pack(recbuf, rec->len);

    atomic_set((atomic64_t *)&rhomf->rh_off, cpu_to_omf64(rec->offset));
}

/* Record unpack routines */

uint64_t
wal_reclen_total(const void *inbuf)
{
    const struct wal_rechdr_omf *rhomf = inbuf;

    return wal_rechdr_len() + omf_rh_len(rhomf);
}

static HSE_ALWAYS_INLINE uint64_t
wal_rec_off(const void *inbuf)
{
    const struct wal_rechdr_omf *rhomf = inbuf;

    return omf_rh_off(rhomf);
}

bool
wal_rec_skip(const void *inbuf)
{
    return (wal_rec_off(inbuf) >= WAL_ROFF_RECOV_ERR);
}

bool
wal_rec_is_eorg(const void *inbuf)
{
    const struct wal_rechdr_omf *rhomf = inbuf;

    return omf_rh_flags(rhomf) & WAL_FLAGS_EORG;
}

bool
wal_rec_is_txncommit(const void *inbuf)
{
    const struct wal_rechdr_omf *rhomf = inbuf;

    return (omf_rh_type(rhomf) == WAL_RT_TXCOMMIT);
}

bool
wal_rec_is_txnmeta(const void *inbuf)
{
    const struct wal_rechdr_omf *rhomf = inbuf;

    return (omf_rh_type(rhomf) == WAL_RT_TXBEGIN ||
            omf_rh_type(rhomf) == WAL_RT_TXABORT ||
            omf_rh_type(rhomf) == WAL_RT_TXCOMMIT);
}

static HSE_ALWAYS_INLINE bool
wal_rec_cksum_valid(const char *inbuf)
{
    const struct wal_rechdr_omf *rhomf = (const void *)inbuf;
    size_t len;
    uint32_t crc, ignore = offsetof(struct wal_rechdr_omf, rh_cksum) + sizeof(rhomf->rh_cksum);

    len = wal_reclen_total(inbuf);
    crc = crc32c(0, inbuf + ignore, len - ignore);

    return (crc == omf_rh_cksum(rhomf));
}

void
wal_update_minmax_seqno(const void *buf, struct wal_minmax_info *info)
{
    const struct wal_rechdr_omf *rhomf = buf;
    uint32_t rtype = omf_rh_type(rhomf);
    bool nontx, txcom;

    nontx = wal_rectype_nontxn(rtype);
    txcom = wal_rectype_txncommit(rtype);

    if (nontx || txcom) {
        const struct wal_rec_omf *r = buf;
        const struct wal_txnrec_omf *tr = buf;
        uint64_t seqno = nontx ? omf_r_seqno(r) : omf_tr_seqno(tr);

        info->min_seqno = min_t(uint64_t, info->min_seqno, seqno);
        info->max_seqno = max_t(uint64_t, info->max_seqno, seqno);
    }
}

void
wal_update_minmax_txid(const void *buf, struct wal_minmax_info *info)
{
    const struct wal_rechdr_omf *rhomf = buf;
    uint32_t rtype = omf_rh_type(rhomf);
    bool tx, txmeta;

    tx = wal_rectype_txn(rtype);
    txmeta = wal_rectype_txnmeta(rtype);

    if (tx || txmeta) {
        const struct wal_rec_omf *r = buf;
        const struct wal_txnrec_omf *tr = buf;
        uint64_t txid = tx ? omf_r_txid(r) : omf_tr_txid(tr);

        info->min_txid = min_t(uint64_t, info->min_txid, txid);
        info->max_txid = max_t(uint64_t, info->max_txid, txid);
    }
}

bool
wal_rec_is_valid(
    const void             *inbuf,
    off_t                   foff,
    size_t                  fsize,
    uint64_t               *recoff,
    uint64_t                gen,
    struct wal_minmax_info *info,
    bool                   *eorg)
{
    const struct wal_rechdr_omf *rhomf = inbuf;
    uint64_t roff;
    size_t   len;
    size_t   fbytes_left = fsize - foff;

    *eorg = false;

    if (fbytes_left < wal_rechdr_len())
        return false;

    roff = wal_rec_off(inbuf);

    if (roff == WAL_ROFF_UNRECOV_ERR)
        return false;

    if (*recoff != 0 && roff != WAL_ROFF_RECOV_ERR && roff != *recoff)
        return false;

    if ((omf_rh_flags(rhomf) & WAL_FLAGS_MASK) != 0)
        return false;

    if (omf_rh_type(rhomf) > WAL_RT_TYPE_MAX)
        return false;

    len = omf_rh_len(rhomf);
    if (len > (wal_reclen() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX + 2 * alignof(uint64_t)))
        return false;

    if (fbytes_left < wal_rechdr_len() + len)
        return false;

    if (!wal_rec_cksum_valid(inbuf))
        return false;

    if (omf_rh_gen(rhomf) > gen)
        return false;

    if (omf_rh_rsvd(rhomf) != 0)
        return false;

    if (!wal_rec_skip(inbuf) && info) {
        uint64_t gen;

        wal_update_minmax_seqno(inbuf, info);
        wal_update_minmax_txid(inbuf, info);

        gen = omf_rh_gen(rhomf);
        info->min_gen = min_t(uint64_t, info->min_gen, gen);
        info->max_gen = max_t(uint64_t, info->max_gen, gen);
    }

    if (wal_rec_is_eorg(inbuf))
        *eorg = true;

    if (*recoff == 0 && roff != WAL_ROFF_RECOV_ERR)
        *recoff = roff;

    return true;
}

static HSE_ALWAYS_INLINE void
wal_rechdr_unpack(const void *inbuf, struct wal_rec *rec)
{
    const struct wal_rechdr_omf *rhomf = inbuf;
    struct wal_rechdr *hdr = &rec->hdr;

    hdr->off = omf_rh_off(rhomf);
    hdr->cksum = omf_rh_cksum(rhomf);
    hdr->flags = omf_rh_flags(rhomf);
    hdr->rid = omf_rh_rid(rhomf);
    hdr->gen = omf_rh_gen(rhomf);
    hdr->type = omf_rh_type(rhomf);
    hdr->len = omf_rh_len(rhomf);
}

void
wal_rec_unpack(const char *inbuf, struct wal_rec *rec)
{
    const struct wal_rec_omf *romf = (const void *)inbuf;
    size_t rlen = wal_reclen();
    size_t kvalign = alignof(uint64_t);
    size_t klen, vxlen;
    const void *kdata;
    void *vdata = NULL;

    wal_rechdr_unpack(inbuf, rec);

    rec->cnid = omf_r_cnid(romf);
    rec->txid = omf_r_txid(romf);
    rec->seqno = omf_r_seqno(romf);
    rec->op = omf_r_op(romf);

    klen = omf_r_klen(romf);
    assert(klen != 0);
    kdata = inbuf + rlen;
    kvs_ktuple_init(&rec->kt, kdata, klen);

    vxlen = omf_r_vxlen(romf);
    if (vxlen > 0)
        vdata = PTR_ALIGN((void *)rec->kt.kt_data + klen, kvalign);
    kvs_vtuple_init(&rec->vt, vdata, vxlen);
}

void
wal_txn_rechdr_finish(void *recbuf, size_t len, uint64_t offset)
{
    struct wal_rechdr_omf *rhomf = recbuf;

    wal_rechdr_crc_pack(recbuf, len);
    atomic_set((atomic64_t *)&rhomf->rh_off, cpu_to_omf64(offset));
}

void
wal_txn_rec_pack(uint64_t txid, uint64_t seqno, uint64_t cid, void *outbuf)
{
    struct wal_txnrec_omf *tromf = outbuf;

    omf_set_tr_txid(tromf, txid);
    omf_set_tr_seqno(tromf, seqno);
    omf_set_tr_cid(tromf, cid);
}

void
wal_txn_rec_unpack(const void *inbuf, struct wal_txmeta_rec *trec)
{
    const struct wal_rechdr_omf *rhomf = inbuf;
    const struct wal_txnrec_omf *tromf = inbuf;

    trec->rid = omf_rh_rid(rhomf);
    trec->gen = omf_rh_gen(rhomf);
    trec->txid = omf_tr_txid(tromf);
    trec->cseqno = omf_tr_seqno(tromf);
    trec->cid = omf_tr_cid(tromf);
}

uint32_t
wal_txn_reclen(void)
{
    return sizeof(struct wal_txnrec_omf);
}

void
wal_filehdr_pack(
    uint32_t                magic,
    uint32_t                version,
    struct wal_minmax_info *info,
    off_t                   soff,
    off_t                   eoff,
    bool                    close,
    void                   *outbuf)
{
    struct wal_filehdr_omf *fhomf = outbuf;
    uint32_t crc;
    uint32_t ignore = sizeof(fhomf->fh_cksum);
    uint32_t len = sizeof(*fhomf);

    omf_set_fh_magic(fhomf, magic);
    omf_set_fh_version(fhomf, version);
    omf_set_fh_close(fhomf, close ? 1 : 0);
    omf_set_fh_mingen(fhomf, info->min_gen);
    omf_set_fh_maxgen(fhomf, info->max_gen);
    omf_set_fh_minseqno(fhomf, info->min_seqno);
    omf_set_fh_maxseqno(fhomf, info->max_seqno);
    omf_set_fh_mintxid(fhomf, info->min_txid);
    omf_set_fh_maxtxid(fhomf, info->max_txid);
    omf_set_fh_startoff(fhomf, soff);
    omf_set_fh_endoff(fhomf, eoff);

    crc = crc32c(0, outbuf + ignore, len - ignore);
    omf_set_fh_cksum(fhomf, crc);
}

merr_t
wal_filehdr_unpack(
    const void             *inbuf,
    uint32_t                magic,
    uint32_t                version,
    bool                   *close,
    off_t                  *soff,
    off_t                  *eoff,
    struct wal_minmax_info *info)
{
    const struct wal_filehdr_omf *fhomf = inbuf;
    uint32_t crc, crcomf;
    uint32_t ignore = sizeof(fhomf->fh_cksum);
    uint32_t len = sizeof(*fhomf);

    *close = (omf_fh_close(fhomf) == 1);
    *soff = omf_fh_startoff(fhomf);
    *eoff = omf_fh_endoff(fhomf);

    info->min_seqno = omf_fh_minseqno(fhomf);
    info->max_seqno = omf_fh_maxseqno(fhomf);
    info->min_gen = omf_fh_mingen(fhomf);
    info->max_gen = omf_fh_maxgen(fhomf);
    info->min_txid = omf_fh_mintxid(fhomf);
    info->max_txid = omf_fh_maxtxid(fhomf);

    crc = crc32c(0, inbuf + ignore, len - ignore);
    crcomf = omf_fh_cksum(fhomf);
    if (crc != crcomf) {
        const struct wal_filehdr_omf ref = {0};

        return ((memcmp(fhomf, &ref, sizeof(*fhomf)) == 0) ? merr(ENODATA) : merr(EBADMSG));
    }

    if (magic != omf_fh_magic(fhomf))
        return merr(EBADMSG);

    if (version != omf_fh_version(fhomf))
        return merr(EPROTO); /* version mismatch, no upgrade support yet */

    return 0;
}
