/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c.h>

#include <hse/ikvdb/tuple.h>
#include <hse/ikvdb/wal.h>
#include <hse/util/page.h>
#include <hse/util/platform.h>

#include "wal_omf.h"
#include "wal_replay.h"

static HSE_ALWAYS_INLINE uint64_t
crc_valid_bit_set(uint32_t crc32)
{
    return ((1ull << CRC_VALID_SHIFT) | crc32);
}

static HSE_ALWAYS_INLINE bool
crc_valid_bit_isset(uint64_t crc)
{
    return (((crc & CRC_VALID_MASK) >> CRC_VALID_SHIFT) == 1);
}

void
wal_rechdr_pack(enum wal_rec_type rtype, uint64_t rid, size_t tlen, uint64_t gen, void *outbuf)
{
    struct wal_rechdr_omf *rhomf = outbuf;

    atomic_set((atomic_ulong *)&rhomf->rh_off, 0);
    omf_set_rh_flags(rhomf, WAL_FLAGS_MORG);
    omf_set_rh_gen(rhomf, gen);
    omf_set_rh_type(rhomf, rtype);
    omf_set_rh_len(rhomf, tlen - wal_rechdr_len(WAL_VERSION)); /* exclude record hdr */
    omf_set_rh_rid(rhomf, rid);
    omf_set_rh_rsvd(rhomf, 0);
}

uint32_t
wal_rechdr_len(uint32_t version)
{
    switch (version) {
    case WAL_VERSION1:
        return sizeof(struct wal_rechdr_omf_v1);

    case WAL_VERSION:
        return sizeof(struct wal_rechdr_omf);

    default:
        abort();
    }
}

void
wal_rechdr_crc_pack(char *recbuf, size_t len)
{
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;
    uint64_t crc;
    uint32_t crc32;
    uint32_t ignore = offsetof(struct wal_rechdr_omf, rh_cksum) + sizeof(rhomf->rh_cksum);

    crc32 = crc32c(0, recbuf + ignore, len - ignore);
    crc = crc_valid_bit_set(crc32);
    omf_set_rh_cksum(rhomf, crc);
}

void
wal_rec_pack(
    enum wal_op op,
    uint64_t cnid,
    uint64_t txid,
    uint32_t klen,
    size_t vxlen,
    void *outbuf)
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
wal_reclen(uint32_t version)
{
    switch (version) {
    case WAL_VERSION1:
        return sizeof(struct wal_rec_omf_v1);

    case WAL_VERSION:
        return sizeof(struct wal_rec_omf);

    default:
        abort();
    }
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

    atomic_set((atomic_ulong *)&rhomf->rh_off, cpu_to_omf64(rec->offset));
}

/* Record unpack routines */

bool
wal_rec_skip(struct wal_rechdr *hdr)
{
    return (hdr->off >= WAL_ROFF_RECOV_ERR);
}

bool
wal_rec_is_txnmeta(struct wal_rechdr *hdr)
{
    return (
        hdr->type == WAL_RT_TXBEGIN || hdr->type == WAL_RT_TXABORT || hdr->type == WAL_RT_TXCOMMIT);
}

static HSE_ALWAYS_INLINE bool
wal_rec_cksum_valid_v1(const char *inbuf)
{
    const struct wal_rechdr_omf_v1 *rhomf = (const void *)inbuf;
    size_t len;
    uint32_t crc, ignore = offsetof(struct wal_rechdr_omf_v1, rh_cksum) + sizeof(rhomf->rh_cksum);

    len = wal_rechdr_len(WAL_VERSION1) + omf_rh_len_v1(rhomf);
    crc = crc32c(0, inbuf + ignore, len - ignore);

    return (crc == omf_rh_cksum_v1(rhomf));
}

static HSE_ALWAYS_INLINE bool
wal_rec_cksum_valid_latest(const char *inbuf)
{
    const struct wal_rechdr_omf *rhomf = (const void *)inbuf;
    size_t len;
    uint64_t crc;
    uint32_t crc32, ignore = offsetof(struct wal_rechdr_omf, rh_cksum) + sizeof(rhomf->rh_cksum);

    len = wal_rechdr_len(WAL_VERSION) + omf_rh_len(rhomf);
    crc32 = crc32c(0, inbuf + ignore, len - ignore);
    crc = omf_rh_cksum(rhomf);

    return ((crc32 == (crc & CRC_MASK)) && crc_valid_bit_isset(crc));
}

static HSE_ALWAYS_INLINE bool
wal_rec_cksum_valid(const char *inbuf, uint32_t version)
{
    switch (version) {
    case WAL_VERSION1:
        return wal_rec_cksum_valid_v1(inbuf);

    case WAL_VERSION:
        return wal_rec_cksum_valid_latest(inbuf);

    default:
        abort();
    }
}

void
wal_update_minmax_seqno(const void *buf, uint32_t rtype, struct wal_minmax_info *info)
{
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
wal_update_minmax_txid(const void *buf, uint32_t rtype, struct wal_minmax_info *info)
{
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
    const void *inbuf,
    off_t foff,
    size_t fsize,
    uint64_t *recoff,
    uint64_t gen,
    uint32_t version,
    struct wal_rechdr *hdr,
    struct wal_minmax_info *info)
{
    uint64_t roff;
    size_t len;
    size_t fbytes_left = fsize - foff;

    if (fbytes_left < wal_rechdr_len(version))
        return false;

    wal_rechdr_unpack(inbuf, version, hdr);

    roff = hdr->off;
    if (roff == WAL_ROFF_UNRECOV_ERR)
        return false;

    if (*recoff != 0 && roff != WAL_ROFF_RECOV_ERR && roff != *recoff)
        return false;

    if ((hdr->flags & WAL_FLAGS_MASK) != 0)
        return false;

    if (hdr->type > WAL_RT_TYPE_MAX)
        return false;

    len = hdr->len;
    if (len >
        (wal_reclen(version) + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX + 2 * sizeof(uint64_t)))
        return false;

    if (fbytes_left < wal_rechdr_len(version) + len)
        return false;

    if (!wal_rec_cksum_valid(inbuf, version))
        return false;

    if (hdr->gen > gen)
        return false;

    if (hdr->rsvd != 0)
        return false;

    if (!wal_rec_skip(hdr) && info) {
        wal_update_minmax_seqno(inbuf, hdr->type, info);
        wal_update_minmax_txid(inbuf, hdr->type, info);

        info->min_gen = min_t(uint64_t, info->min_gen, hdr->gen);
        info->max_gen = max_t(uint64_t, info->max_gen, hdr->gen);
    }

    if (*recoff == 0 && roff != WAL_ROFF_RECOV_ERR)
        *recoff = roff;

    return true;
}

static HSE_ALWAYS_INLINE void
wal_rechdr_unpack_v1(const void *inbuf, struct wal_rechdr *hdr)
{
    const struct wal_rechdr_omf_v1 *rhomf = inbuf;

    hdr->off = omf_rh_off_v1(rhomf);
    hdr->flags = omf_rh_flags_v1(rhomf);
    hdr->cksum = omf_rh_cksum_v1(rhomf);
    hdr->rid = omf_rh_rid_v1(rhomf);
    hdr->gen = omf_rh_gen_v1(rhomf);
    hdr->type = omf_rh_type_v1(rhomf);
    hdr->len = omf_rh_len_v1(rhomf);
    hdr->rsvd = omf_rh_rsvd_v1(rhomf);
}

static HSE_ALWAYS_INLINE void
wal_rechdr_unpack_latest(const void *inbuf, struct wal_rechdr *hdr)
{
    const struct wal_rechdr_omf *rhomf = inbuf;

    hdr->off = omf_rh_off(rhomf);
    hdr->flags = omf_rh_flags(rhomf);
    hdr->cksum = omf_rh_cksum(rhomf);
    hdr->rid = omf_rh_rid(rhomf);
    hdr->gen = omf_rh_gen(rhomf);
    hdr->type = omf_rh_type(rhomf);
    hdr->len = omf_rh_len(rhomf);
    hdr->rsvd = omf_rh_rsvd(rhomf);
}

void
wal_rechdr_unpack(const void *inbuf, uint32_t version, struct wal_rechdr *hdr)
{
    switch (version) {

    case WAL_VERSION1:
        wal_rechdr_unpack_v1(inbuf, hdr);
        break;

    case WAL_VERSION:
        wal_rechdr_unpack_latest(inbuf, hdr);
        break;

    default:
        abort();
    }
}

static void
wal_rec_unpack_v1(const char *inbuf, struct wal_rechdr *hdr, struct wal_rec *rec)
{
    const struct wal_rec_omf_v1 *romf = (const void *)inbuf;
    size_t rlen = wal_reclen(WAL_VERSION1);
    size_t kvalign = sizeof(uint64_t);
    size_t klen, vxlen;
    const void *kdata;
    void *vdata = NULL;

    rec->hdr = *hdr;
    rec->cnid = omf_r_cnid_v1(romf);
    rec->txid = omf_r_txid_v1(romf);
    rec->seqno = omf_r_seqno_v1(romf);
    rec->op = omf_r_op_v1(romf);

    klen = omf_r_klen_v1(romf);
    assert(klen != 0);
    kdata = inbuf + rlen;
    kvs_ktuple_init(&rec->kt, kdata, klen);

    vxlen = omf_r_vxlen_v1(romf);
    if (vxlen > 0)
        vdata = PTR_ALIGN((void *)rec->kt.kt_data + klen, kvalign);
    kvs_vtuple_init(&rec->vt, vdata, vxlen);
}

static void
wal_rec_unpack_latest(const char *inbuf, struct wal_rechdr *hdr, struct wal_rec *rec)
{
    const struct wal_rec_omf *romf = (const void *)inbuf;
    size_t rlen = wal_reclen(WAL_VERSION);
    size_t kvalign = sizeof(uint64_t);
    size_t klen, vxlen;
    const void *kdata;
    void *vdata = NULL;

    rec->hdr = *hdr;
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
wal_rec_unpack(const char *inbuf, struct wal_rechdr *hdr, uint32_t version, struct wal_rec *rec)
{
    switch (version) {
    case WAL_VERSION1:
        wal_rec_unpack_v1(inbuf, hdr, rec);
        break;

    case WAL_VERSION:
        wal_rec_unpack_latest(inbuf, hdr, rec);
        break;

    default:
        abort();
    }
}

void
wal_txn_rechdr_finish(void *recbuf, size_t len, uint64_t offset)
{
    struct wal_rechdr_omf *rhomf = recbuf;

    wal_rechdr_crc_pack(recbuf, len);
    atomic_set((atomic_ulong *)&rhomf->rh_off, cpu_to_omf64(offset));
}

void
wal_txn_rec_pack(uint64_t txid, uint64_t seqno, uint64_t cid, void *outbuf)
{
    struct wal_txnrec_omf *tromf = outbuf;

    omf_set_tr_txid(tromf, txid);
    omf_set_tr_seqno(tromf, seqno);
    omf_set_tr_cid(tromf, cid);
}

static void
wal_txn_rec_unpack_v1(const void *inbuf, struct wal_rechdr *hdr, struct wal_txmeta_rec *trec)
{
    const struct wal_txnrec_omf_v1 *tromf = inbuf;

    trec->rid = hdr->rid;
    trec->gen = hdr->gen;
    trec->txid = omf_tr_txid_v1(tromf);
    trec->cseqno = omf_tr_seqno_v1(tromf);
    trec->cid = omf_tr_cid_v1(tromf);
}

static void
wal_txn_rec_unpack_latest(const void *inbuf, struct wal_rechdr *hdr, struct wal_txmeta_rec *trec)
{
    const struct wal_txnrec_omf *tromf = inbuf;

    trec->rid = hdr->rid;
    trec->gen = hdr->gen;
    trec->txid = omf_tr_txid(tromf);
    trec->cseqno = omf_tr_seqno(tromf);
    trec->cid = omf_tr_cid(tromf);
}

void
wal_txn_rec_unpack(
    const void *inbuf,
    struct wal_rechdr *hdr,
    uint32_t version,
    struct wal_txmeta_rec *trec)
{
    switch (version) {
    case WAL_VERSION1:
        wal_txn_rec_unpack_v1(inbuf, hdr, trec);
        break;

    case WAL_VERSION:
        wal_txn_rec_unpack_latest(inbuf, hdr, trec);
        break;

    default:
        abort();
    }
}

uint32_t
wal_txn_reclen(uint32_t version)
{
    switch (version) {
    case WAL_VERSION1:
        return sizeof(struct wal_txnrec_omf_v1);

    case WAL_VERSION:
        return sizeof(struct wal_txnrec_omf);

    default:
        abort();
    }
}

void
wal_filehdr_pack(
    uint32_t magic,
    uint32_t version,
    struct wal_minmax_info *info,
    off_t soff,
    off_t eoff,
    bool close,
    void *outbuf)
{
    struct wal_filehdr_omf *fhomf = outbuf;
    uint64_t crc;
    uint32_t crc32;
    uint32_t ignore = sizeof(fhomf->fh_cksum);
    uint32_t len = sizeof(*fhomf);

    omf_set_fh_magic(fhomf, magic);
    omf_set_fh_version(fhomf, version);
    omf_set_fh_rsvd(fhomf, 0);
    omf_set_fh_close(fhomf, close ? 1 : 0);
    omf_set_fh_mingen(fhomf, info->min_gen);
    omf_set_fh_maxgen(fhomf, info->max_gen);
    omf_set_fh_minseqno(fhomf, info->min_seqno);
    omf_set_fh_maxseqno(fhomf, info->max_seqno);
    omf_set_fh_mintxid(fhomf, info->min_txid);
    omf_set_fh_maxtxid(fhomf, info->max_txid);
    omf_set_fh_startoff(fhomf, soff);
    omf_set_fh_endoff(fhomf, eoff);

    crc32 = crc32c(0, outbuf, len - ignore);
    crc = crc_valid_bit_set(crc32);
    omf_set_fh_cksum(fhomf, crc);
}

static merr_t
wal_filehdr_unpack_v1(
    const void *inbuf,
    uint32_t magic,
    bool *close,
    off_t *soff,
    off_t *eoff,
    struct wal_minmax_info *info)
{
    const struct wal_filehdr_omf_v1 *fhomf = inbuf;
    uint32_t crc, crcomf;
    uint32_t ignore = sizeof(fhomf->fh_cksum);
    uint32_t len = sizeof(*fhomf);

    *close = (omf_fh_close_v1(fhomf) == 1);
    *soff = omf_fh_startoff_v1(fhomf);
    *eoff = omf_fh_endoff_v1(fhomf);

    info->min_seqno = omf_fh_minseqno_v1(fhomf);
    info->max_seqno = omf_fh_maxseqno_v1(fhomf);
    info->min_gen = omf_fh_mingen_v1(fhomf);
    info->max_gen = omf_fh_maxgen_v1(fhomf);
    info->min_txid = omf_fh_mintxid_v1(fhomf);
    info->max_txid = omf_fh_maxtxid_v1(fhomf);

    crc = crc32c(0, inbuf + ignore, len - ignore);
    crcomf = omf_fh_cksum_v1(fhomf);
    if (crc != crcomf) {
        const struct wal_filehdr_omf_v1 ref = { 0 };

        return ((memcmp(fhomf, &ref, sizeof(*fhomf)) == 0) ? merr(ENODATA) : merr(EBADMSG));
    }

    if ((magic != omf_fh_magic_v1(fhomf)) || (WAL_VERSION1 != omf_fh_version_v1(fhomf)))
        return merr(EBADMSG);

    return 0;
}

static merr_t
wal_filehdr_unpack_latest(
    const void *inbuf,
    uint32_t magic,
    bool *close,
    off_t *soff,
    off_t *eoff,
    struct wal_minmax_info *info)
{
    const struct wal_filehdr_omf *fhomf = inbuf;
    uint64_t crc;
    uint32_t crc32;
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

    crc32 = crc32c(0, inbuf, len - ignore);
    crc = omf_fh_cksum(fhomf);
    if ((crc32 != (crc & CRC_MASK)) || !crc_valid_bit_isset(crc)) {
        const struct wal_filehdr_omf ref = { 0 };

        return ((memcmp(fhomf, &ref, sizeof(*fhomf)) == 0) ? merr(ENODATA) : merr(EBADMSG));
    }

    if ((magic != omf_fh_magic(fhomf)) || (WAL_VERSION != omf_fh_version(fhomf)))
        return merr(EBADMSG);

    return 0;
}

merr_t
wal_filehdr_unpack(
    const void *inbuf,
    uint32_t magic,
    uint32_t version,
    bool *close,
    off_t *soff,
    off_t *eoff,
    struct wal_minmax_info *info)
{
    merr_t err;

    switch (version) {
    case WAL_VERSION1:
        err = wal_filehdr_unpack_v1(inbuf, magic, close, soff, eoff, info);
        break;

    case WAL_VERSION:
        err = wal_filehdr_unpack_latest(inbuf, magic, close, soff, eoff, info);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}
