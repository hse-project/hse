/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c/crc32c.h>
#include <hse_util/platform.h>

#include "wal_omf.h"

void
wal_rechdr_pack(enum wal_rec_type rtype, u64 rid, size_t kvlen, char *outbuf)
{
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)outbuf;

    omf_set_rh_type(rhomf, rtype);
    omf_set_rh_rid(rhomf, rid);
    omf_set_rh_len(rhomf, wal_rec_len() + kvlen - wal_rechdr_len());
}

uint
wal_rechdr_len(void)
{
    return sizeof(struct wal_rechdr_omf);
}

void
wal_rechdr_crc_pack(char *recbuf, size_t len)
{
    struct wal_rechdr_omf *rhomf = (struct wal_rechdr_omf *)recbuf;
    uint crc;
    u8 crclen = sizeof(crc);

    crc = crc32c(0, recbuf + crclen, len - crclen);

    omf_set_rh_cksum(rhomf, crc);
}

void
wal_rec_pack(enum wal_op op, u64 cnid, u64 txid, u64 seqno, uint klen, size_t vxlen, char *outbuf)
{
    struct wal_rec_omf *romf = (struct wal_rec_omf *)outbuf;

    omf_set_r_op(romf, op);
    omf_set_r_klen(romf, klen);
    omf_set_r_cnid(romf, cnid);
    omf_set_r_txid(romf, txid);
    omf_set_r_seqno(romf, seqno);
    omf_set_r_vxlen(romf, vxlen);
}

uint
wal_rec_len(void)
{
    return sizeof(struct wal_rec_omf);
}
