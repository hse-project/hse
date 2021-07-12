/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/slab.h>
#include <hse_util/event_counter.h>

#include "cndb_internal.h"
#include <hse_ikvdb/cndb.h>

/********************************************************************
 *
 * Unpacking of CNDB mdc omf records.
 *
 *******************************************************************/

/*
 * Type CNDB_TYPE_VERSION
 */
struct cndb_upg_history cndb_ver_unpackt[] = {
    {
        omf_cndb_ver_unpack,
        CNDB_VERSION4,
    },
};

/*
 * Type CNDB_TYPE_META
 */
struct cndb_upg_history cndb_meta_unpackt[] = {
    {
        omf_cndb_meta_unpack,
        CNDB_VERSION11,
    },
};

/*
 * Type CNDB_TYPE_INFO and CNDB_TYPE_INFOD
 */
struct cndb_upg_history cndb_info_unpackt[] = {
    {
        omf_cndb_info_unpack_v7,
        CNDB_VERSION7,
    },
    {
        omf_cndb_info_unpack_v9,
        CNDB_VERSION9,
    },
    {
        omf_cndb_info_unpack,
        CNDB_VERSION10,
    },
};

/*
 * Type CNDB_TYPE_TX
 */
struct cndb_upg_history cndb_tx_unpackt[] = {
    {
        omf_cndb_tx_unpack_v4,
        CNDB_VERSION4,
    },
    {
        omf_cndb_tx_unpack_v5,
        CNDB_VERSION5,
    },
    {
        omf_cndb_tx_unpack,
        CNDB_VERSION12,
    },
};

/*
 * Type CNDB_TYPE_TXC
 */
struct cndb_upg_history cndb_txc_unpackt[] = {
    {
        omf_cndb_txc_unpack_v4,
        CNDB_VERSION4,
    },
    {
        omf_cndb_txc_unpack,
        CNDB_VERSION5,
    },
};

/*
 * Type CNDB_TYPE_TXM
 */
struct cndb_upg_history cndb_txm_unpackt[] = {
    {
        omf_cndb_txm_unpack_v8,
        CNDB_VERSION4,
    },
    {
        omf_cndb_txm_unpack,
        CNDB_VERSION9,
    },
};

/*
 * Type CNDB_TYPE_TXD
 */
struct cndb_upg_history cndb_txd_unpackt[] = {
    {
        omf_cndb_txd_unpack,
        CNDB_VERSION4,
    },
};

/*
 * Type CNDB_TYPE_ACK
 */
struct cndb_upg_history cndb_ack_unpackt[] = {
    {
        omf_cndb_ack_unpack,
        CNDB_VERSION4,
    },
};

/*
 * Type CNDB_TYPE_NAK
 */
struct cndb_upg_history cndb_nak_unpackt[] = {
    {
        omf_cndb_nak_unpack,
        CNDB_VERSION4,
    },
};

/**
 * cndb_unpackt
 *  Indexed by the record type.
 *  For each record type, points to the set of unpacking functions.
 */
struct cndb_upg_histlen cndb_unpackt[] = {
    { NULL, 0 },                                     /* 0                 */
    { cndb_ver_unpackt, NELEM(cndb_ver_unpackt) },   /* CNDB_TYPE_VERSION */
    { cndb_info_unpackt, NELEM(cndb_info_unpackt) }, /* CNDB_TYPE_INFO    */
    { cndb_info_unpackt, NELEM(cndb_info_unpackt) }, /* CNDB_TYPE_INFOD   */
    { cndb_tx_unpackt, NELEM(cndb_tx_unpackt) },     /* CNDB_TYPE_TX      */
    { cndb_ack_unpackt, NELEM(cndb_ack_unpackt) },   /* CNDB_TYPE_ACK     */
    { cndb_nak_unpackt, NELEM(cndb_nak_unpackt) },   /* CNDB_TYPE_NAK     */
    { cndb_txc_unpackt, NELEM(cndb_txc_unpackt) },   /* CNDB_TYPE_TXC     */
    { cndb_txm_unpackt, NELEM(cndb_txm_unpackt) },   /* CNDB_TYPE_TXM     */
    { cndb_txd_unpackt, NELEM(cndb_txd_unpackt) },   /* CNDB_TYPE_TXD     */
    { cndb_meta_unpackt, NELEM(cndb_meta_unpackt) }, /* CNDB_TYPE_META    */
};

merr_t
omf_cndb_ver_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                  type;
    u32                  len;
    struct cndb_ver *    mtv = (void *)mtu;
    struct cndb_ver_omf *ver_omf = omf;

    type = omf_cnhdr_type(&(ver_omf->hdr));

    if (type != CNDB_TYPE_VERSION) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_ver);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtv->mtv_magic = omf_cnver_magic(ver_omf);
    mtv->mtv_version = omf_cnver_version(ver_omf);
    mtv->mtv_captgt = omf_cnver_captgt(ver_omf);

    return 0;
}

merr_t
omf_cndb_meta_unpack(void *omf_blob, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    struct cndb_meta_omf *omf = omf_blob;
    struct cndb_meta *    mte;
    u32                   type;
    u32                   len;

    type = omf_cnhdr_type(&(omf->hdr));
    if (type != CNDB_TYPE_META) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }

    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }

    len = sizeof(struct cndb_meta);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }

    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mte = &mtu->e;
    mtu->h.mth_type = type;

    mte->mte_seqno_max = omf_cnmeta_seqno_max(omf);

    return 0;
}

merr_t
omf_cndb_info_unpack(void *omf_blob, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    struct cndb_info_omf *omf = omf_blob;
    struct cndb_info *    mti;
    u32                   type;
    u32                   len;

    type = omf_cnhdr_type(&(omf->hdr));
    if (type != CNDB_TYPE_INFO && type != CNDB_TYPE_INFOD) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }

    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }

    len = sizeof(struct cndb_info) + omf_cninfo_metasz(omf);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }

    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mti = &mtu->i;
    mtu->h.mth_type = type;

    mti->mti_fanout_bits = omf_cninfo_fanout_bits(omf);
    mti->mti_sfx_len = omf_cninfo_sfx_len(omf);
    mti->mti_prefix_len = omf_cninfo_prefix_len(omf);
    mti->mti_prefix_pivot = omf_cninfo_prefix_pivot(omf);
    mti->mti_flags = omf_cninfo_flags(omf);
    mti->mti_cnid = omf_cninfo_cnid(omf);
    mti->mti_metasz = omf_cninfo_metasz(omf);

    omf_cninfo_name(omf, mti->mti_name, sizeof(mti->mti_name));
    memcpy(mti->mti_meta, omf->cninfo_meta, mti->mti_metasz);

    return 0;
}

merr_t
omf_cndb_info_unpack_v9(void *omf_blob, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    struct cndb_info_omf *omf = omf_blob;
    struct cndb_info *    mti;
    u32                   type;
    u32                   len;

    type = omf_cnhdr_type(&(omf->hdr));
    if (type != CNDB_TYPE_INFO && type != CNDB_TYPE_INFOD) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }

    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }

    len = sizeof(struct cndb_info) + omf_cninfo_metasz(omf);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }

    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mti = &mtu->i;
    mtu->h.mth_type = type;

    mti->mti_fanout_bits = omf_cninfo_fanout_bits(omf);
    mti->mti_prefix_len = omf_cninfo_prefix_len(omf);
    mti->mti_prefix_pivot = omf_cninfo_prefix_pivot(omf);
    mti->mti_flags = omf_cninfo_flags(omf);
    mti->mti_cnid = omf_cninfo_cnid(omf);
    mti->mti_metasz = omf_cninfo_metasz(omf);

    omf_cninfo_name(omf, mti->mti_name, sizeof(mti->mti_name));
    memcpy(mti->mti_meta, omf->cninfo_meta, mti->mti_metasz);

    return 0;
}

merr_t
omf_cndb_info_unpack_v7(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                      type;
    u32                      len;
    struct cndb_info *       mti = (void *)mtu;
    struct cndb_info_omf_v7 *info_omf = omf;

    type = omf_cnhdr_type(&(info_omf->hdr));
    if (type != CNDB_TYPE_INFO && type != CNDB_TYPE_INFOD) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_info) + omf_cninfo_metasz_v7(info_omf);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mti->mti_fanout_bits = omf_cninfo_fanout_bits_v7(info_omf);
    mti->mti_prefix_len = omf_cninfo_prefix_len_v7(info_omf);
    mti->mti_flags = omf_cninfo_flags_v7(info_omf);
    mti->mti_cnid = omf_cninfo_cnid_v7(info_omf);
    mti->mti_metasz = omf_cninfo_metasz_v7(info_omf);
    omf_cninfo_name_v7(info_omf, mti->mti_name, sizeof(mti->mti_name));
    memcpy(mti->mti_meta, info_omf->cninfo_meta, mti->mti_metasz);

    return 0;
}

merr_t
omf_cndb_tx_unpack_v4(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                    type;
    u32                    len;
    struct cndb_tx *       mtx = (void *)mtu;
    struct cndb_tx_omf_v4 *tx_omf = omf;

    type = omf_cnhdr_type(&(tx_omf->hdr));
    if (type != CNDB_TYPE_TX) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_tx);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtx->mtx_id = omf_tx_id_v4(tx_omf);
    mtx->mtx_nc = omf_tx_nc_v4(tx_omf);
    mtx->mtx_nd = omf_tx_nd_v4(tx_omf);
    mtx->mtx_seqno = omf_tx_seqno_v4(tx_omf);
    mtx->mtx_ingestid = CNDB_INVAL_INGESTID;

    return 0;
}

merr_t
omf_cndb_tx_unpack_v5(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                     type;
    u32                     len;
    struct cndb_tx *        mtx = (void *)mtu;
    struct cndb_tx_omf_v5 *tx_omf = omf;

    type = omf_cnhdr_type(&(tx_omf->hdr));
    if (type != CNDB_TYPE_TX) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_tx);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtx->mtx_id = omf_tx_id_v5(tx_omf);
    mtx->mtx_nc = omf_tx_nc_v5(tx_omf);
    mtx->mtx_nd = omf_tx_nd_v5(tx_omf);
    mtx->mtx_seqno = omf_tx_seqno_v5(tx_omf);
    mtx->mtx_ingestid = omf_tx_ingestid_v5(tx_omf);
    mtx->mtx_txhorizon = CNDB_INVAL_HORIZON;

    return 0;
}

merr_t
omf_cndb_tx_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                 type;
    u32                 len;
    struct cndb_tx *    mtx = (void *)mtu;
    struct cndb_tx_omf *tx_omf = omf;

    type = omf_cnhdr_type(&(tx_omf->hdr));
    if (type != CNDB_TYPE_TX) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_tx);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtx->mtx_id = omf_tx_id(tx_omf);
    mtx->mtx_nc = omf_tx_nc(tx_omf);
    mtx->mtx_nd = omf_tx_nd(tx_omf);
    mtx->mtx_seqno = omf_tx_seqno(tx_omf);
    mtx->mtx_ingestid = omf_tx_ingestid(tx_omf);
    mtx->mtx_txhorizon = omf_tx_txhorizon(tx_omf);

    return 0;
}

merr_t
omf_cndb_txc_unpack_v4(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                     type;
    u32                     len;
    int                     i;
    u32                     mtc_flags;
    struct cndb_txc *       mtc = (void *)mtu;
    struct cndb_oid *       mto = NULL;
    struct cndb_oid_omf *   omo = NULL;
    struct cndb_txc_omf_v4 *txc_omf = omf;

    type = omf_cnhdr_type(&(txc_omf->hdr));
    if (type != CNDB_TYPE_TXC) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_txc) +
          sizeof(struct cndb_oid) * (omf_txc_kcnt_v4(txc_omf) + omf_txc_vcnt_v4(txc_omf));
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtc->mtc_cnid = omf_txc_cnid_v4(txc_omf);
    mtc->mtc_id = omf_txc_id_v4(txc_omf);
    mtc->mtc_tag = omf_txc_tag_v4(txc_omf);
    mtc->mtc_kcnt = omf_txc_kcnt_v4(txc_omf);
    mtc->mtc_vcnt = omf_txc_vcnt_v4(txc_omf);

    mtc_flags = omf_txc_flags_v4(txc_omf);
    if (mtc_flags & CNDB_TXF_KEEPV)
        mtc->mtc_keepvbc = mtc->mtc_vcnt;
    else
        mtc->mtc_keepvbc = 0;

    if (omf_txc_mcnt_v4(txc_omf) != 0)
        hse_alog(HSE_NOTICE "cndb tx %lu OMF contains meta blocks, ignored", (ulong)mtc->mtc_id);

    mto = (void *)&mtc[1];
    omo = (void *)&txc_omf[1];
    for (i = 0; i < mtc->mtc_kcnt; i++)
        mto[i].mmtx_oid = omf_cndb_oid(&omo[i]);

    mto += mtc->mtc_kcnt;
    omo += mtc->mtc_kcnt;
    for (i = 0; i < mtc->mtc_vcnt; i++)
        mto[i].mmtx_oid = omf_cndb_oid(&omo[i]);

    return 0;
}

merr_t
omf_cndb_txc_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                  type;
    u32                  len;
    int                  i;
    struct cndb_txc *    mtc = (void *)mtu;
    struct cndb_oid *    mto = NULL;
    struct cndb_oid_omf *omo = NULL;
    struct cndb_txc_omf *txc_omf = omf;

    type = omf_cnhdr_type(&(txc_omf->hdr));
    if (type != CNDB_TYPE_TXC) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_txc) +
          sizeof(struct cndb_oid) * (omf_txc_kcnt(txc_omf) + omf_txc_vcnt(txc_omf));
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtc->mtc_cnid = omf_txc_cnid(txc_omf);
    mtc->mtc_id = omf_txc_id(txc_omf);
    mtc->mtc_tag = omf_txc_tag(txc_omf);
    mtc->mtc_kcnt = omf_txc_kcnt(txc_omf);
    mtc->mtc_vcnt = omf_txc_vcnt(txc_omf);
    mtc->mtc_keepvbc = omf_txc_keepvbc(txc_omf);
    if (omf_txc_mcnt(txc_omf) != 0)
        hse_alog(HSE_NOTICE "cndb tx %lu OMF contains meta blocks, ignored", (ulong)mtc->mtc_id);

    mto = (void *)&mtc[1];
    omo = (void *)&txc_omf[1];
    for (i = 0; i < mtc->mtc_kcnt; i++)
        mto[i].mmtx_oid = omf_cndb_oid(&omo[i]);

    mto += mtc->mtc_kcnt;
    omo += mtc->mtc_kcnt;
    for (i = 0; i < mtc->mtc_vcnt; i++)
        mto[i].mmtx_oid = omf_cndb_oid(&omo[i]);

    return 0;
}

merr_t
omf_cndb_txm_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                  type;
    u32                  len;
    struct cndb_txm *    mtm = (void *)mtu;
    struct cndb_txm_omf *txm_omf = omf;

    type = omf_cnhdr_type(&(txm_omf->hdr));
    if (type != CNDB_TYPE_TXM) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_txm);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtm->mtm_cnid = omf_txm_cnid(txm_omf);
    mtm->mtm_id = omf_txm_id(txm_omf);
    mtm->mtm_tag = omf_txm_tag(txm_omf);
    mtm->mtm_level = omf_txm_level(txm_omf);
    mtm->mtm_offset = omf_txm_offset(txm_omf);
    mtm->mtm_dgen = omf_txm_dgen(txm_omf);
    mtm->mtm_vused = omf_txm_vused(txm_omf);
    mtm->mtm_compc = omf_txm_compc(txm_omf);
    mtm->mtm_scatter = omf_txm_scatter(txm_omf);

    return 0;
}

merr_t
omf_cndb_txm_unpack_v8(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                     type;
    u32                     len;
    struct cndb_txm *       mtm = (void *)mtu;
    struct cndb_txm_omf_v8 *txm_omf = omf;

    type = omf_cnhdr_type(&(txm_omf->hdr));
    if (type != CNDB_TYPE_TXM) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_txm);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtm->mtm_cnid = omf_txm_cnid_v8(txm_omf);
    mtm->mtm_id = omf_txm_id_v8(txm_omf);
    mtm->mtm_tag = omf_txm_tag_v8(txm_omf);
    mtm->mtm_level = omf_txm_level_v8(txm_omf);
    mtm->mtm_offset = omf_txm_offset_v8(txm_omf);
    mtm->mtm_dgen = omf_txm_dgen_v8(txm_omf);
    mtm->mtm_vused = omf_txm_vused_v8(txm_omf);
    mtm->mtm_compc = omf_txm_compc_v8(txm_omf);
    mtm->mtm_scatter = mtm->mtm_vused ? max_t(u32, mtm->mtm_compc, 1) : 0;

    return 0;
}

merr_t
omf_cndb_txd_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                  type;
    u32                  len;
    int                  i;
    struct cndb_txd *    mtd = (void *)mtu;
    struct cndb_oid *    mto = NULL;
    struct cndb_oid_omf *omo = NULL;
    struct cndb_txd_omf *txd_omf = omf;

    type = omf_cnhdr_type(&(txd_omf->hdr));
    if (type != CNDB_TYPE_TXD) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_oid) * omf_txd_n_oids(txd_omf) + sizeof(struct cndb_txd);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtd->mtd_cnid = omf_txd_cnid(txd_omf);
    mtd->mtd_id = omf_txd_id(txd_omf);
    mtd->mtd_tag = omf_txd_tag(txd_omf);
    mtd->mtd_n_oids = omf_txd_n_oids(txd_omf);

    mto = (void *)&mtd[1];
    omo = (void *)&txd_omf[1];
    for (i = 0; i < mtd->mtd_n_oids; i++)
        mto[i].mmtx_oid = omf_cndb_oid(&omo[i]);

    return 0;
}

merr_t
omf_cndb_ack_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                  type;
    u32                  len;
    struct cndb_ack *    mta = (void *)mtu;
    struct cndb_ack_omf *ack_omf = omf;

    type = omf_cnhdr_type(&(ack_omf->hdr));
    if (type != CNDB_TYPE_ACK) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_ack);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mta->mta_txid = omf_ack_txid(ack_omf);
    mta->mta_type = omf_ack_type(ack_omf);
    mta->mta_tag = omf_ack_tag(ack_omf);
    mta->mta_cnid = omf_ack_cnid(ack_omf);

    return 0;
}

merr_t
omf_cndb_nak_unpack(void *omf, u32 ver, union cndb_mtu *mtu, u32 *plen)
{
    u32                  type;
    u32                  len;
    struct cndb_nak *    mtn = (void *)mtu;
    struct cndb_nak_omf *nak_omf = omf;

    type = omf_cnhdr_type(&(nak_omf->hdr));
    if (type != CNDB_TYPE_NAK) {
        hse_alog(
            HSE_ERR "%s: Invalid record type %u for this "
                    "unpacking function, version %u",
            __func__,
            type,
            ver);
        return merr(EINVAL);
    }
    if ((mtu == NULL) && (plen == NULL)) {
        hse_alog(HSE_ERR "%s: NULL length pointer, version %u", __func__, ver);
        return merr(EINVAL);
    }
    len = sizeof(struct cndb_nak);
    if (mtu == NULL) {
        /* The caller wants only the length */
        *plen = len;
        return 0;
    }
    if (plen && (*plen < len)) {
        hse_alog(HSE_ERR "%s: Receive buffer too small, version %u", __func__, ver);
        return merr(EINVAL);
    }

    mtu->h.mth_type = type;
    mtn->mtn_txid = omf_nak_txid(nak_omf);

    return 0;
}

cndb_unpack_fn *
cndb_unpack_get_fn(struct cndb_upg_histlen *upghl, u32 cndb_version)
{
    struct cndb_upg_history *cur = NULL;
    int                      beg = 0;
    int                      end = upghl->uhl_len;
    int                      mid;

    while (beg < end) {
        mid = (beg + end) / 2;
        cur = &upghl->uhl_his[mid];
        if (cndb_version == cur->uh_ver)
            return cur->uh_fn;
        else if (cndb_version > cur->uh_ver)
            beg = mid + 1;
        else
            end = mid;
    }

    if (ev(end == 0, HSE_ERR))
        /* not found */
        return NULL;

    return upghl->uhl_his[end - 1].uh_fn;
}

merr_t
omf2mtx(union cndb_mtu *mtu, u32 *mtulen, void *omf, u32 cndb_version)
{
    struct cndb_upg_histlen *upghl;
    cndb_unpack_fn *         fn;
    u32                      type;
    merr_t                   err;

    type = omf_cnhdr_type(omf);
    if (type >= NELEM(cndb_unpackt)) {
        hse_alog(
            HSE_ERR "%s: Unknown cndb mdc record type %u version "
                    "%u",
            __func__,
            type,
            cndb_version);
        return merr(EPROTO);
    }
    upghl = &cndb_unpackt[type];
    fn = cndb_unpack_get_fn(upghl, cndb_version);
    if (fn == NULL) {
        hse_alog(
            HSE_ERR "The cndb metadata (version %u type %u) is too"
                    " old, the KVDB can't be opened",
            cndb_version,
            type);
        return merr(EPROTO);
    }
    err = fn(omf, cndb_version, mtu, mtulen);

    return ev(err, HSE_ERR);
}

merr_t
omf2len(void *omf, u32 cndb_version, u32 *len)
{
    struct cndb_upg_histlen *upghl;
    cndb_unpack_fn *         fn;
    u32                      type;
    merr_t                   err;

    *len = 0;

    type = omf_cnhdr_type(omf);
    if (type >= NELEM(cndb_unpackt)) {
        hse_alog(
            HSE_ERR "%s: Unknown cndb mdc record type %u version "
                    "%u",
            __func__,
            type,
            cndb_version);
        return merr(EPROTO);
    }
    upghl = &cndb_unpackt[type];
    fn = cndb_unpack_get_fn(upghl, cndb_version);
    if (fn == NULL) {
        hse_alog(
            HSE_ERR "The cndb metadata (version %u type %u) is too"
                    " old, the KVDB can't be opened",
            cndb_version,
            type);
        return merr(EPROTO);
    }
    err = fn(omf, cndb_version, NULL, len);

    return ev(err, HSE_ERR);
}

merr_t
cndb_record_unpack(u32 cndb_version, struct cndb_hdr_omf *buf, union cndb_mtu **mtu)
{
    u32    mtlen;
    merr_t err;

    *mtu = NULL;
    err = omf2len(buf, cndb_version, &mtlen);
    if (ev(err, HSE_ERR) || !mtlen)
        return err;

    *mtu = calloc(1, mtlen);
    if (*mtu == NULL)
        return merr(ev(ENOMEM, HSE_ERR));

    err = omf2mtx(*mtu, &mtlen, buf, cndb_version);
    if (ev(err, HSE_ERR)) {
        free(*mtu);
        *mtu = NULL;
        return err;
    }
    return 0;
}
