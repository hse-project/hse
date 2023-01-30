/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/ikvdb/omf_version.h>

#include <hse/ikvdb/cn.h>

#include "cn/kvset.h"

#include "omf.h"

/*
 * OMF Write functions
 */

static void
cndb_hdr_omf_init(struct cndb_hdr_omf *omf, int type, int len)
{
    assert(len >= sizeof(*omf));

    omf_set_cnhdr_type(omf, type);
    omf_set_cnhdr_len(omf, len - sizeof(*omf));
}

merr_t
cndb_omf_ver_write(struct mpool_mdc *mdc, size_t captgt)
{
    struct cndb_ver_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_VERSION, sizeof(omf));

    omf_set_cnver_magic(&omf, CNDB_MAGIC);
    omf_set_cnver_version(&omf, CNDB_VERSION);
    omf_set_cnver_captgt(&omf, captgt);

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_meta_write(struct mpool_mdc *mdc, uint64_t seqno_max)
{
    struct cndb_meta_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_META, sizeof(omf));

    omf_set_cnmeta_seqno_max(&omf, 0);

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_kvs_add_write(
    struct mpool_mdc   *mdc,
    uint64_t            cnid,
    struct kvs_cparams *cp,
    const char         *name)
{
    struct cndb_kvs_add_omf omf = {0};
    uint32_t flags = 0;

    if (cp->kvs_ext01)
        flags |= CN_CFLAG_CAPPED;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_KVS_ADD, sizeof(omf));

    omf_set_kvs_add_pfxlen(&omf, cp->pfx_len);
    omf_set_kvs_add_cnid(&omf, cnid);
    omf_set_kvs_add_flags(&omf, flags);
    omf_set_kvs_add_name(&omf, (unsigned char *)name, strlen(name));

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_kvs_del_write(struct mpool_mdc *mdc, uint64_t cnid)
{
    struct cndb_kvs_del_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_KVS_DEL, sizeof(omf));

    omf_set_kvs_del_cnid(&omf, cnid);

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_txstart_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          seqno,
    uint64_t          ingestid,
    uint64_t          txhorizon,
    uint16_t          add_cnt,
    uint16_t          del_cnt)
{
    struct cndb_txstart_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_TXSTART, sizeof(omf));

    omf_set_txstart_id(&omf, txid);
    omf_set_txstart_seqno(&omf, seqno);
    omf_set_txstart_ingestid(&omf, ingestid);
    omf_set_txstart_txhorizon(&omf, txhorizon);
    omf_set_txstart_add_cnt(&omf, add_cnt);
    omf_set_txstart_del_cnt(&omf, del_cnt);

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_kvset_add_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          cnid,
    uint64_t          kvsetid,
    uint64_t          nodeid,
    uint64_t          dgen_hi,
    uint64_t          dgen_lo,
    uint64_t          vused,
    uint64_t          vgarb,
    uint32_t          compc,
    uint16_t          rule,
    uint64_t          hblkid,
    uint32_t          kblkc,
    uint64_t         *kblkv,
    uint32_t          vblkc,
    uint64_t         *vblkv)
{
    struct cndb_kvset_add_omf *omf;
    struct cndb_oid_omf *oid;
    size_t sz = sizeof(*omf) + (kblkc + vblkc) * sizeof(*oid);
    unsigned char buf[1024];
    merr_t err;
    int i;

    omf = (void *)buf;
    if (sz > sizeof(buf)) {
        omf = malloc(sz);
        if (!omf)
            return merr(ENOMEM);
    }

    oid = (void *)(omf + 1);

    cndb_hdr_omf_init(&omf->hdr, CNDB_TYPE_KVSET_ADD, sz);

    omf_set_kvset_add_txid(omf, txid);
    omf_set_kvset_add_cnid(omf, cnid);
    omf_set_kvset_add_kvsetid(omf, kvsetid);
    omf_set_kvset_add_nodeid(omf, nodeid);
    omf_set_kvset_add_dgen_hi(omf, dgen_hi);
    omf_set_kvset_add_dgen_lo(omf, dgen_lo);
    omf_set_kvset_add_vused(omf, vused);
    omf_set_kvset_add_vgarb(omf, vgarb);
    omf_set_kvset_add_compc(omf, compc);
    omf_set_kvset_add_rule(omf, rule);
    omf_set_kvset_add_kblk_cnt(omf, kblkc);
    omf_set_kvset_add_vblk_cnt(omf, vblkc);
    omf_set_kvset_add_hblkid(omf, hblkid);

    for (i = 0; i < kblkc; i++)
        omf_set_cndb_oid(&oid[i], kblkv[i]);

    oid += kblkc;
    for (i = 0; i < vblkc; i++)
        omf_set_cndb_oid(&oid[i], vblkv[i]);

    err =  mpool_mdc_append(mdc, omf, sz, false);

    if (sz > sizeof(buf))
        free(omf);

    return err;
}

merr_t
cndb_omf_kvset_del_write(
    struct mpool_mdc *mdc,
    uint64_t          txid,
    uint64_t          cnid,
    uint64_t          kvsetid)
{
    struct cndb_kvset_del_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_KVSET_DEL, sizeof(omf));

    omf_set_kvset_del_txid(&omf, txid);
    omf_set_kvset_del_cnid(&omf, cnid);
    omf_set_kvset_del_kvsetid(&omf, kvsetid);

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_kvset_move_write(
    struct mpool_mdc *mdc,
    uint64_t          cnid,
    uint64_t          src_nodeid,
    uint64_t          tgt_nodeid,
    uint32_t          kvset_idc,
    const uint64_t   *kvset_idv)
{
    struct cndb_kvset_move_omf *omf_move;
    struct cndb_kvsetid_omf *omf_ks_idv;
    uint8_t buf[sizeof(*omf_move) + 512];
    size_t sz;
    merr_t err;

    omf_move = (void *)buf;

    sz = sizeof(*omf_move) + kvset_idc * sizeof(*omf_ks_idv);
    if (sz > sizeof(buf)) {
        omf_move = malloc(sz);
        if (!omf_move)
            return merr(ENOMEM);
    }

    omf_ks_idv = (void *)(omf_move + 1);

    cndb_hdr_omf_init(&omf_move->hdr, CNDB_TYPE_KVSET_MOVE, sz);

    omf_set_kvset_move_cnid(omf_move, cnid);
    omf_set_kvset_move_src_nodeid(omf_move, src_nodeid);
    omf_set_kvset_move_tgt_nodeid(omf_move, tgt_nodeid);
    omf_set_kvset_move_kvset_idc(omf_move, kvset_idc);

    for (uint32_t i = 0; i < kvset_idc; i++)
        omf_set_cndb_kvsetid(&omf_ks_idv[i], kvset_idv[i]);

    err = mpool_mdc_append(mdc, omf_move, sz, true);

    if (sz > sizeof(buf))
        free(omf_move);

    return err;
}

merr_t
cndb_omf_ack_write(
    struct mpool_mdc *mdc,
    uint64_t             txid,
    uint64_t             cnid,
    unsigned int         type,
    uint64_t             kvsetid)
{
    struct cndb_ack_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_ACK, sizeof(omf));

    omf_set_ack_txid(&omf, txid);
    omf_set_ack_type(&omf, type);
    omf_set_ack_cnid(&omf, cnid);
    omf_set_ack_kvsetid(&omf, kvsetid);

    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

merr_t
cndb_omf_nak_write(struct mpool_mdc *mdc, uint64_t txid)
{
    struct cndb_nak_omf omf;

    cndb_hdr_omf_init(&omf.hdr, CNDB_TYPE_NAK, sizeof(omf));

    omf_set_nak_txid(&omf, txid);
    return mpool_mdc_append(mdc, &omf, sizeof(omf), true);
}

/*
 * OMF Read functions
 */

void
cndb_omf_ver_read(
    struct cndb_ver_omf *omf,
    uint32_t            *magic,
    uint16_t            *version,
    size_t              *size)
{
    *magic = omf_cnver_magic(omf);
    *version = omf_cnver_version(omf);
    *size = omf_cnver_captgt(omf);
}

void
cndb_omf_meta_read(
    struct cndb_meta_omf *omf,
    uint64_t            *seqno_max)
{
    *seqno_max = omf_cnmeta_seqno_max(omf);
}

void
cndb_omf_kvs_add_read(
    struct cndb_kvs_add_omf *omf,
    struct kvs_cparams      *cp,
    uint64_t                *cnid,
    char                    *namebuf,
    size_t                   namebufsz)
{
    cp->pfx_len = omf_kvs_add_pfxlen(omf);
    cp->kvs_ext01 = omf_kvs_add_flags(omf) & CN_CFLAG_CAPPED;

    *cnid = omf_kvs_add_cnid(omf);
    omf_kvs_add_name(omf, namebuf, namebufsz);
}

void
cndb_omf_kvs_del_read(
    struct cndb_kvs_del_omf *omf,
    uint64_t                *cnid)
{
    *cnid = omf_kvs_del_cnid(omf);
}

void
cndb_omf_txstart_read(
    struct cndb_txstart_omf *omf,
    uint64_t                *txid,
    uint64_t                *seqno,
    uint64_t                *ingestid,
    uint64_t                *txhorizon,
    uint16_t                *add_cnt,
    uint16_t                *del_cnt)
{
    *txid = omf_txstart_id(omf);
    *seqno = omf_txstart_seqno(omf);
    *ingestid = omf_txstart_ingestid(omf);
    *txhorizon = omf_txstart_txhorizon(omf);
    *add_cnt = omf_txstart_add_cnt(omf);
    *del_cnt = omf_txstart_del_cnt(omf);
}

/* This function modifies the input buffer (omf).
 */
void
cndb_omf_kvset_add_read(
    struct cndb_kvset_add_omf *omf,
    uint64_t                  *txid,
    uint64_t                  *cnid,
    uint64_t                  *kvsetid,
    uint64_t                  *nodeid,
    uint64_t                  *hblkid,
    unsigned int              *kblkc,
    uint64_t                 **kblkv,
    unsigned int              *vblkc,
    uint64_t                 **vblkv,
    struct kvset_meta         *km)
{
    struct cndb_oid_omf *mbidv;
    uint64_t *blkidp;
    unsigned int nblks;

    int i;

    *txid = omf_kvset_add_txid(omf);
    *cnid = omf_kvset_add_cnid(omf);
    *kvsetid = omf_kvset_add_kvsetid(omf);
    *nodeid = omf_kvset_add_nodeid(omf);

    *hblkid = omf_kvset_add_hblkid(omf);

    km->km_dgen_hi = omf_kvset_add_dgen_hi(omf);
    km->km_dgen_lo = omf_kvset_add_dgen_lo(omf);
    km->km_vused = omf_kvset_add_vused(omf);
    km->km_vgarb = omf_kvset_add_vgarb(omf);
    km->km_compc = omf_kvset_add_compc(omf);
    km->km_rule = omf_kvset_add_rule(omf);

    *kblkc = omf_kvset_add_kblk_cnt(omf);
    *vblkc = omf_kvset_add_vblk_cnt(omf);

    nblks = *kblkc + *vblkc;
    mbidv = (void *)(omf + 1);
    blkidp = (void *)(omf + 1); /* Reuse the buffer that holds the mblock ids in the omf format. */

    for (i = 0; i < nblks; i++)
        blkidp[i] = omf_cndb_oid(&mbidv[i]);

    *kblkv = blkidp;
    *vblkv = blkidp + (*kblkc);
}

void
cndb_omf_kvset_del_read(
    struct cndb_kvset_del_omf *omf,
    uint64_t                  *txid,
    uint64_t                  *cnid,
    uint64_t                  *kvsetid)
{
    *txid = omf_kvset_del_txid(omf);
    *cnid = omf_kvset_del_cnid(omf);
    *kvsetid = omf_kvset_del_kvsetid(omf);
}

/* This function modifies the input buffer (omf).
 */
void
cndb_omf_kvset_move_read(
    struct cndb_kvset_move_omf *omf,
    uint64_t                   *cnid,
    uint64_t                   *src_nodeid,
    uint64_t                   *tgt_nodeid,
    uint32_t                   *kvset_idc,
    uint64_t                  **kvset_idv)
{
    struct cndb_kvsetid_omf *omf_ks_idv;
    uint64_t *idv;

    *cnid = omf_kvset_move_cnid(omf);
    *src_nodeid = omf_kvset_move_src_nodeid(omf);
    *tgt_nodeid = omf_kvset_move_tgt_nodeid(omf);
    *kvset_idc = omf_kvset_move_kvset_idc(omf);

    omf_ks_idv = (void *)(omf + 1);
    idv = (void *)(omf + 1); /* Reuse input buffer */

    for (uint32_t i = 0; i < *kvset_idc; i++)
        idv[i] = omf_cndb_kvsetid(&omf_ks_idv[i]);

    *kvset_idv = idv;
}

void
cndb_omf_ack_read(
    struct cndb_ack_omf *omf,
    uint64_t            *txid,
    uint64_t            *cnid,
    unsigned int        *type,
    uint64_t            *kvsetid)
{
    *txid = omf_ack_txid(omf);
    *cnid = omf_ack_cnid(omf);
    *type = omf_ack_type(omf);
    *kvsetid = omf_ack_kvsetid(omf);
}

void
cndb_omf_nak_read(
    struct cndb_nak_omf *omf,
    uint64_t            *txid)
{
    *txid = omf_nak_txid(omf);
}
