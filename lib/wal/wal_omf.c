/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c/crc32c.h>
#include <hse_util/platform.h>
#include <hse_util/page.h>

#include <hse_ikvdb/wal.h>
#include <hse_ikvdb/tuple.h>

#include "wal_omf.h"
#include "wal_replay.h"

void
wal_rechdr_pack(enum wal_rec_type rtype, u64 rid, size_t kvlen, void *outbuf)
{
    struct wal_rechdr_omf *rhomf = outbuf;

    atomic64_set((atomic64_t *)&rhomf->rh_off, 0);
    omf_set_rh_flags(rhomf, WAL_FLAGS_MORG);
    omf_set_rh_gen(rhomf, 0);
    omf_set_rh_type(rhomf, rtype);
    omf_set_rh_len(rhomf, wal_rec_len() + kvlen - wal_rechdr_len());
    omf_set_rh_rid(rhomf, rid);
}

uint
wal_rechdr_len(void)
{
    return sizeof(struct wal_rechdr_omf);
}

void
wal_rechdr_crc_pack(const char *recbuf, size_t len)
{
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;
    uint crc;
    uint ignore = offsetof(struct wal_rechdr_omf, rh_cksum) + sizeof(rhomf->rh_cksum);

    crc = crc32c(0, recbuf + ignore, len - ignore);
    omf_set_rh_cksum(rhomf, crc);
}

void
wal_rec_pack(enum wal_op op, u64 cnid, u64 txid, uint klen, size_t vxlen, void *outbuf)
{
    struct wal_rec_omf *romf = outbuf;

    omf_set_r_op(romf, op);
    omf_set_r_klen(romf, klen);
    omf_set_r_cnid(romf, cnid);
    omf_set_r_txid(romf, txid);
    omf_set_r_seqno(romf, 0);
    omf_set_r_vxlen(romf, vxlen);
}

uint
wal_rec_len(void)
{
    return sizeof(struct wal_rec_omf);
}

void
wal_rec_finish(struct wal_record *rec, u64 seqno, u64 gen)
{
    char *recbuf = rec->recbuf;
    struct wal_rec_omf *romf = (struct wal_rec_omf *)recbuf;
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;

    omf_set_rh_gen(rhomf, gen);
    omf_set_r_seqno(romf, seqno);
    wal_rechdr_crc_pack(recbuf, rec->len);

    atomic64_set((atomic64_t *)&rhomf->rh_off, cpu_to_le64(rec->offset));
}

/* Record unpack routines */

u64
wal_rec_total_len(const char *inbuf)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;

    return wal_rechdr_len() + omf_rh_len(rhomf);
}

static HSE_ALWAYS_INLINE u64
wal_rec_off(const char *inbuf)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;

    return omf_rh_off(rhomf);
}

bool
wal_rec_skip(const char *inbuf)
{
    return (wal_rec_off(inbuf) == U64_MAX - 1);
}

bool
wal_rec_is_borg(const char *inbuf)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;

    return omf_rh_flags(rhomf) & WAL_FLAGS_BORG;
}

bool
wal_rec_is_eorg(const char *inbuf)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;

    return omf_rh_flags(rhomf) & WAL_FLAGS_EORG;
}

bool
wal_rec_is_morg(const char *inbuf)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;

    return omf_rh_flags(rhomf) & WAL_FLAGS_MORG;
}

static HSE_ALWAYS_INLINE bool
wal_rec_cksum_valid(const char *inbuf)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;
    size_t len;
    uint crc, ignore = offsetof(struct wal_rechdr_omf, rh_cksum) + sizeof(rhomf->rh_cksum);

    len = wal_rec_total_len(inbuf);
    crc = crc32c(0, inbuf + ignore, len - ignore);

    return (crc == omf_rh_cksum(rhomf));
}

bool
wal_rec_is_valid(const char *inbuf, off_t *offset, u64 gen)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;
    off_t off;

    off = wal_rec_off(inbuf);

    if (off == U64_MAX)
        return false;

    if (((u32)omf_rh_flags(rhomf) & WAL_FLAGS_MASK) != 0)
        return false;

    if (omf_rh_type(rhomf) > WAL_RT_TYPE_MAX)
        return false;

    if (omf_rh_len(rhomf) >
        (wal_rec_len() + HSE_KVS_KEY_LEN_MAX + HSE_KVS_VALUE_LEN_MAX + 2 * alignof(uint64_t)))
        return false;

    if (omf_rh_gen(rhomf) > gen)
        return false;

    if (*offset != 0 && off != U64_MAX - 1 && off != *offset)
        return false;

    if (*offset == 0 && off != U64_MAX - 1)
        *offset = off;

    return wal_rec_cksum_valid(inbuf);
}

static HSE_ALWAYS_INLINE void
wal_rechdr_unpack(const char *inbuf, struct wal_rec *rec)
{
    struct wal_rechdr_omf *rhomf = (void *)inbuf;
    struct wal_rec_hdr *hdr = &rec->hdr;

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
    struct wal_rec_omf *romf = (void *)inbuf;
    size_t rlen = wal_rec_len(), kvalign = alignof(uint64_t), klen, vxlen;
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
wal_txn_rechdr_pack(enum wal_rec_type rtype, u64 rid, u64 gen, void *outbuf)
{
    struct wal_rechdr_omf *rhomf = outbuf;

    omf_set_rh_flags(rhomf, WAL_FLAGS_MORG);
    omf_set_rh_gen(rhomf, gen);
    omf_set_rh_type(rhomf, rtype);
    omf_set_rh_rid(rhomf, rid);
    omf_set_rh_len(rhomf, wal_txn_rec_len() - wal_rechdr_len());
}

void
wal_txn_rechdr_finish(void *recbuf, size_t len, u64 offset)
{
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;

    wal_rechdr_crc_pack(recbuf, len);
    atomic64_set((atomic64_t *)&rhomf->rh_off, cpu_to_le64(offset));
}

void
wal_txn_rec_pack(u64 txid, u64 seqno, void *outbuf)
{
    struct wal_txnrec_omf *tromf = outbuf;

    omf_set_tr_txid(tromf, txid);
    omf_set_tr_seqno(tromf, seqno);
}

uint
wal_txn_rec_len(void)
{
    return sizeof(struct wal_txnrec_omf);
}

void
wal_filehdr_pack(
    u32                     magic,
    u32                     version,
    struct wal_minmax_info *info,
    off_t                   soff,
    off_t                   eoff,
    bool                    close,
    void                   *outbuf)
{
    struct wal_filehdr_omf *fhomf = outbuf;
    uint crc;
    uint ignore = sizeof(fhomf->fh_cksum);
    uint len = sizeof(*fhomf);

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
    u32                    *magic,
    u32                    *version,
    bool                   *close,
    off_t                  *soff,
    off_t                  *eoff,
    struct wal_minmax_info *info)
{
    const struct wal_filehdr_omf *fhomf = inbuf;
    uint crc;
    uint ignore = sizeof(fhomf->fh_cksum);
    uint len = sizeof(*fhomf);

    *magic = omf_fh_magic(fhomf);
    *version = omf_fh_version(fhomf);
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
    if (crc != omf_fh_cksum(fhomf))
        return merr(EBADMSG);

    return 0;
}
