/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c/crc32c.h>
#include <hse_util/platform.h>

#include <hse_ikvdb/wal.h>
#include "wal_omf.h"

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
wal_rechdr_crc_pack(void *recbuf, size_t len)
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

void
wal_txn_rechdr_pack(enum wal_rec_type rtype, u64 rid, void *outbuf)
{
    struct wal_rechdr_omf *rhomf = outbuf;

    omf_set_rh_flags(rhomf, WAL_FLAGS_MORG);
    omf_set_rh_gen(rhomf, 0);
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

    crc = crc32c(0, outbuf + ignore, len - ignore);
    omf_set_fh_cksum(fhomf, crc);
}
