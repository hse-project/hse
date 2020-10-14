/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_omf_internal.h"

/* C1_TYPE_INFO */
struct c1_unpack_hinfo c1_inf_unpackt[] = {
    {
        omf_c1_info_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_DESC */
struct c1_unpack_hinfo c1_dsc_unpackt[] = {
    {
        omf_c1_desc_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_INGEST */
struct c1_unpack_hinfo c1_ing_unpackt[] = {
    {
        omf_c1_ingest_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_KVLOG */
struct c1_unpack_hinfo c1_kvl_unpackt[] = {
    {
        omf_c1_kvlog_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_KVB */
struct c1_unpack_hinfo c1_kvb_unpackt[] = {
    {
        omf_c1_kvb_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_KVT */
struct c1_unpack_hinfo c1_kvt_unpackt[] = {
    {
        omf_c1_kvtuple_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_COMPLETE */
struct c1_unpack_hinfo c1_cmp_unpackt[] = {
    {
        omf_c1_complete_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_RESET */
struct c1_unpack_hinfo c1_rst_unpackt[] = {
    {
        omf_c1_reset_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_TXN */
struct c1_unpack_hinfo c1_txn_unpackt[] = {
    {
        omf_c1_treetxn_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_VT */
struct c1_unpack_hinfo c1_vt_unpackt[] = {
    {
        omf_c1_vtuple_unpack,
        C1_VERSION1,
    },
};

/* C1_TYPE_MBLK */
struct c1_unpack_hinfo c1_mblk_unpackt[] = {
    {
        omf_c1_mblk_unpack,
        C1_VERSION1,
    },
};

struct c1_unpack_type c1_unpackt[] = {
    { c1_inf_unpackt, NELEM(c1_inf_unpackt) },   /* C1_TYPE_INFO */
    { c1_dsc_unpackt, NELEM(c1_dsc_unpackt) },   /* C1_TYPE_DESC */
    { c1_ing_unpackt, NELEM(c1_ing_unpackt) },   /* C1_TYPE_INGEST */
    { c1_kvl_unpackt, NELEM(c1_kvl_unpackt) },   /* C1_TYPE_KVLOG */
    { c1_kvb_unpackt, NELEM(c1_kvb_unpackt) },   /* C1_TYPE_KVB */
    { c1_kvt_unpackt, NELEM(c1_kvt_unpackt) },   /* C1_TYPE_KVT */
    { c1_cmp_unpackt, NELEM(c1_cmp_unpackt) },   /* C1_TYPE_COMPLETE */
    { c1_rst_unpackt, NELEM(c1_rst_unpackt) },   /* C1_TYPE_RESET */
    { c1_txn_unpackt, NELEM(c1_txn_unpackt) },   /* C1_TYPE_TXN */
    { NULL, 0 },                                 /* C1_TYPE_TXN_BEGIN */
    { NULL, 0 },                                 /* C1_TYPE_TXN_COMMIT */
    { NULL, 0 },                                 /* C1_TYPE_TXN_ABORT */
    { NULL, 0 },                                 /* C1_TYPE_CLOSE */
    { c1_vt_unpackt, NELEM(c1_vt_unpackt) },     /* C1_TYPE_VT */
    { c1_mblk_unpackt, NELEM(c1_mblk_unpackt) }, /* C1_TYPE_MBLK */
};

static inline merr_t
omf_c1_hdr_validate(struct c1_hdr_omf *hdr, u32 len)
{
    u32 hlen;
    u32 l;

    hlen = sizeof(*hdr);
    l = omf_c1hdr_len(hdr);
    if (ev(l != len - hlen)) {
        hse_log(
            HSE_ERR "%s: Invalid record len %u %u for type %u",
            __func__,
            l,
            len - hlen,
            omf_c1hdr_type(hdr));

        return merr(EINVAL);
    }

    return 0;
}

/*
 * Unpack routine for c1 header.
 */
merr_t
omf_c1_header_unpack(char *omf, struct c1_header *hdr)
{
    struct c1_hdr_omf *hdr_omf;

    if (ev(!omf || !hdr))
        return merr(EINVAL);

    hdr_omf = (struct c1_hdr_omf *)omf;

    hdr->c1h_type = omf_c1hdr_type(hdr_omf);
    hdr->c1h_len = omf_c1hdr_len(hdr_omf);

    return 0;
}

u32
omf_c1_header_type(char *omf)
{
    return omf_c1hdr_type((struct c1_hdr_omf *)omf);
}

u32
omf_c1_header_unpack_len(void)
{
    return sizeof(struct c1_hdr_omf);
}

/*
 * Unpack routine for c1 version.
 */
merr_t
omf_c1_ver_unpack(char *omf, struct c1_version *vers)
{
    struct c1_ver_omf *ver_omf;

    merr_t err;
    u32    len;

    if (ev(!omf || !vers))
        return merr(EINVAL);

    len = sizeof(*ver_omf);

    ver_omf = (struct c1_ver_omf *)omf;

    err = omf_c1_hdr_validate(&ver_omf->hdr, len);
    if (ev(err))
        return err;

    vers->c1v_magic = omf_c1ver_magic(ver_omf);
    vers->c1v_version = omf_c1ver_version(ver_omf);

    return 0;
}

/*
 * Version specific unpack routines for other record types.
 */
merr_t
omf_c1_info_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_info_omf *info_omf;
    struct c1_info *    info;

    merr_t err;
    u32    len;

    len = sizeof(*info_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    info_omf = (struct c1_info_omf *)omf;

    err = omf_c1_hdr_validate(&info_omf->hdr, len);
    if (ev(err))
        return err;

    info = &rec->f;

    info->c1i_seqno = omf_c1info_seqno(info_omf);
    info->c1i_gen = omf_c1info_gen(info_omf);
    info->c1i_capacity = omf_c1info_capacity(info_omf);

    return 0;
}

merr_t
omf_c1_desc_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_desc_omf *desc_omf;
    struct c1_desc *    desc;

    merr_t err;
    u32    len;

    len = sizeof(*desc_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    desc_omf = (struct c1_desc_omf *)omf;

    err = omf_c1_hdr_validate(&desc_omf->hdr, len);
    if (ev(err))
        return err;

    desc = &rec->d;

    desc->c1d_oid = omf_c1desc_oid(desc_omf);
    desc->c1d_seqno = omf_c1desc_seqno(desc_omf);
    desc->c1d_state = omf_c1desc_state(desc_omf);
    desc->c1d_gen = omf_c1desc_gen(desc_omf);

    return 0;
}

merr_t
omf_c1_ingest_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_ingest_omf *ing_omf;
    struct c1_ingest *    ingest;

    merr_t err;
    u32    len;

    len = sizeof(*ing_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    ing_omf = (struct c1_ingest_omf *)omf;

    err = omf_c1_hdr_validate(&ing_omf->hdr, len);
    if (ev(err))
        return err;

    ingest = &rec->i;

    ingest->c1ing_seqno = omf_c1ingest_seqno(ing_omf);
    ingest->c1ing_cnid = omf_c1ingest_cnid(ing_omf);
    ingest->c1ing_cntgen = omf_c1ingest_cntgen(ing_omf);
    ingest->c1ing_status = omf_c1ingest_status(ing_omf);

    return 0;
}

merr_t
omf_c1_kvlog_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_kvlog_omf *kv_omf;
    struct c1_log *      log;

    merr_t err;
    u32    len;

    len = sizeof(*kv_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    kv_omf = (struct c1_kvlog_omf *)omf;

    err = omf_c1_hdr_validate(&kv_omf->hdr, len);
    if (ev(err))
        return err;

    log = &rec->l;

    log->c1l_mdcoid1 = omf_c1kvlog_mdcoid1(kv_omf);
    log->c1l_mdcoid2 = omf_c1kvlog_mdcoid2(kv_omf);
    log->c1l_oid = omf_c1kvlog_oid(kv_omf);
    log->c1l_space = omf_c1kvlog_size(kv_omf);
    log->c1l_seqno = omf_c1kvlog_seqno(kv_omf);
    log->c1l_gen = omf_c1kvlog_gen(kv_omf);

    return 0;
}

merr_t
omf_c1_kvb_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_kvbundle_omf *kvb_omf;
    struct c1_kvb *         kvb;

    merr_t err;
    u32    len;

    len = sizeof(*kvb_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    kvb_omf = (struct c1_kvbundle_omf *)omf;

    err = omf_c1_hdr_validate(&kvb_omf->hdr, len);
    if (ev(err))
        return err;

    kvb = &rec->b;

    kvb->c1kvb_seqno = omf_c1kvb_seqno(kvb_omf);
    kvb->c1kvb_gen = omf_c1kvb_gen(kvb_omf);
    kvb->c1kvb_keycount = omf_c1kvb_keycount(kvb_omf);
    kvb->c1kvb_ckeycount = omf_c1kvb_ckeycount(kvb_omf);
    kvb->c1kvb_mutation = omf_c1kvb_mutation(kvb_omf);
    kvb->c1kvb_txnid = omf_c1kvb_txnid(kvb_omf);
    kvb->c1kvb_size = omf_c1kvb_size(kvb_omf);
    kvb->c1kvb_minkey = omf_c1kvb_minkey(kvb_omf);
    kvb->c1kvb_maxkey = omf_c1kvb_maxkey(kvb_omf);
    kvb->c1kvb_minseqno = omf_c1kvb_minseqno(kvb_omf);
    kvb->c1kvb_maxseqno = omf_c1kvb_maxseqno(kvb_omf);
    kvb->c1kvb_ingestid = omf_c1kvb_ingestid(kvb_omf);

    return 0;
}

merr_t
omf_c1_kvtuple_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_kvtuple_omf * kvt_omf;
    struct c1_kvtuple_meta *kvtm;

    if (omf_len)
        *omf_len = sizeof(*kvt_omf);

    if (!omf || !rec)
        return 0;

    kvt_omf = (struct c1_kvtuple_omf *)omf;

    kvtm = &rec->k;

    kvtm->c1kvm_sign = omf_c1kvt_sign(kvt_omf);
    kvtm->c1kvm_klen = omf_c1kvt_klen(kvt_omf);
    kvtm->c1kvm_cnid = omf_c1kvt_cnid(kvt_omf);
    kvtm->c1kvm_xlen = omf_c1kvt_xlen(kvt_omf);
    kvtm->c1kvm_vcount = omf_c1kvt_vcount(kvt_omf);
    kvtm->c1kvm_data = (char *)kvt_omf->c1kvt_data;

    return 0;
}

merr_t
omf_c1_complete_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_complete_omf *cmp_omf;
    struct c1_complete *    cmp;

    merr_t err;
    u32    len;

    len = sizeof(*cmp_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    cmp_omf = (struct c1_complete_omf *)omf;

    err = omf_c1_hdr_validate(&cmp_omf->hdr, len);
    if (ev(err))
        return err;

    cmp = &rec->c;

    cmp->c1c_seqno = omf_c1comp_seqno(cmp_omf);
    cmp->c1c_gen = omf_c1comp_gen(cmp_omf);
    cmp->c1c_kvseqno = omf_c1comp_kvseqno(cmp_omf);

    return 0;
}

merr_t
omf_c1_reset_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_reset_omf *res_omf;
    struct c1_reset *    reset;

    merr_t err;
    u32    len;

    len = sizeof(*res_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    res_omf = (struct c1_reset_omf *)omf;

    err = omf_c1_hdr_validate(&res_omf->hdr, len);
    if (ev(err))
        return err;

    reset = &rec->r;

    reset->c1reset_seqno = omf_c1reset_seqno(res_omf);
    reset->c1reset_gen = omf_c1reset_gen(res_omf);
    reset->c1reset_newseqno = omf_c1reset_newseqno(res_omf);
    reset->c1reset_newgen = omf_c1reset_newgen(res_omf);

    return 0;
}

merr_t
omf_c1_treetxn_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_treetxn_omf *ttxn_omf;
    struct c1_treetxn *    ttxn;

    merr_t err;
    u32    len;

    len = sizeof(*ttxn_omf);
    if (omf_len)
        *omf_len = len;

    if (!omf || !rec)
        return 0;

    ttxn_omf = (struct c1_treetxn_omf *)omf;

    err = omf_c1_hdr_validate(&ttxn_omf->hdr, len);
    if (ev(err))
        return err;

    ttxn = &rec->t;

    ttxn->c1txn_seqno = omf_c1ttxn_seqno(ttxn_omf);
    ttxn->c1txn_gen = omf_c1ttxn_gen(ttxn_omf);
    ttxn->c1txn_id = omf_c1ttxn_id(ttxn_omf);
    ttxn->c1txn_ingestid = omf_c1ttxn_ingestid(ttxn_omf);
    ttxn->c1txn_mutation = omf_c1ttxn_mutation(ttxn_omf);
    ttxn->c1txn_cmd = omf_c1ttxn_cmd(ttxn_omf);
    ttxn->c1txn_flag = omf_c1ttxn_flag(ttxn_omf);

    return 0;
}

merr_t
omf_c1_vtuple_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_vtuple_omf * vt_omf;
    struct c1_vtuple_meta *vtm;

    if (omf_len)
        *omf_len = sizeof(*vt_omf);

    if (!omf || !rec)
        return 0;

    vt_omf = (struct c1_vtuple_omf *)omf;

    vtm = &rec->v;

    vtm->c1vm_sign = omf_c1vt_sign(vt_omf);
    vtm->c1vm_seqno = omf_c1vt_seqno(vt_omf);
    vtm->c1vm_xlen = omf_c1vt_xlen(vt_omf);
    vtm->c1vm_tomb = omf_c1vt_tomb(vt_omf);
    vtm->c1vm_logtype = omf_c1vt_logtype(vt_omf);
    vtm->c1vm_data = (char *)vt_omf->c1vt_data;

    return 0;
}

merr_t
omf_c1_mblk_unpack(char *omf, union c1_record *rec, u32 *omf_len)
{
    struct c1_mblk_omf * mblk_omf;
    struct c1_mblk_meta *mblk;

    if (omf_len)
        *omf_len = sizeof(*mblk_omf);

    if (!omf || !rec)
        return 0;

    mblk_omf = (struct c1_mblk_omf *)omf;

    mblk = &rec->m;

    mblk->c1mblk_id = omf_c1mblk_id(mblk_omf);
    mblk->c1mblk_off = omf_c1mblk_off(mblk_omf);

    return 0;
}

/* Generic interfaces */

static inline merr_t
c1_record_unpack_argcheck(char *omf, union c1_record *rec, u32 *omf_len)
{
    if (ev(!omf || (!rec && !omf_len)))
        return merr(EINVAL);

    return 0;
}

static inline merr_t
c1_record_unpack_typecheck(u32 type)
{
    if (ev((type <= C1_TYPE_BASE) || (type > NELEM(c1_unpackt) + C1_TYPE_BASE)))
        return merr(EPROTO);

    return 0;
}

c1_unpack_hdlr *
c1_record_unpack_hdlr_get(struct c1_unpack_type *upt, u32 ver)
{
    struct c1_unpack_hinfo *inf;

    int beg;
    int end;
    int mid;

    beg = 0;
    end = upt->c1_uverc;

    while (beg < end) {
        mid = (beg + end) / 2;

        inf = &upt->c1_uhinfo[mid];

        if (ver == inf->c1_uver)
            return inf->c1_uhdr;
        else if (ver > inf->c1_uver)
            beg = mid + 1;
        else
            end = mid;
    }

    if (end == 0)
        return NULL;

    return upt->c1_uhinfo[end - 1].c1_uhdr;
}

static merr_t
c1_record_unpack_common(char *omf, u32 ver, u32 type, union c1_record *rec, u32 *omf_len)
{
    c1_unpack_hdlr *       uph;
    struct c1_unpack_type *upt;

    merr_t err;

    err = c1_record_unpack_typecheck(type);
    if (ev(err))
        return err;

    upt = &c1_unpackt[type - C1_TYPE_BASE - 1];

    uph = c1_record_unpack_hdlr_get(upt, ver);
    if (ev(!uph))
        return merr(EPROTO);

    err = uph(omf, rec, omf_len);
    if (ev(err))
        return err;

    return 0;
}

merr_t
c1_record_unpack(char *omf, u32 ver, union c1_record *rec)
{
    u32    type;
    merr_t err;

    err = c1_record_unpack_argcheck(omf, rec, NULL);
    if (ev(err))
        return err;

    type = omf_c1hdr_type((struct c1_hdr_omf *)omf);

    return c1_record_unpack_common(omf, ver, type, rec, NULL);
}

merr_t
c1_record_unpack_bytype(char *omf, u32 type, u32 ver, union c1_record *rec)
{
    merr_t err;

    err = c1_record_unpack_argcheck(omf, rec, NULL);
    if (ev(err))
        return err;

    return c1_record_unpack_common(omf, ver, type, rec, NULL);
}

merr_t
c1_record_omf2len(char *omf, u32 ver, u32 *omf_len)
{
    u32    type;
    merr_t err;

    err = c1_record_unpack_argcheck(omf, NULL, omf_len);
    if (ev(err))
        return err;

    type = omf_c1hdr_type((struct c1_hdr_omf *)omf);

    return c1_record_unpack_common(omf, ver, type, NULL, omf_len);
}

merr_t
c1_record_type2len(u32 type, u32 ver, u32 *omf_len)
{
    if (ev(!omf_len))
        return merr(EINVAL);

    return c1_record_unpack_common(NULL, ver, type, NULL, omf_len);
}
