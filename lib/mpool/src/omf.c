/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>

#include "omf.h"
#include "mblock_file.h"
#include "mblock_fset.h"
#include "mdc_file.h"

static uint32_t
omf_loghdr_crc_get(struct mdc_loghdr_omf *lhomf)
{
    return crc32c(0, (const uint8_t *)lhomf, offsetof(struct mdc_loghdr_omf, lh_crc));
}

merr_t
omf_mdc_loghdr_pack(struct mdc_loghdr *lh, char *outbuf)
{
    struct mdc_loghdr_omf *lhomf;

    lhomf = (struct mdc_loghdr_omf *)outbuf;

    if (lh->vers != MDC_LOGHDR_VERSION)
        return merr(EINVAL);

    omf_set_lh_vers(lhomf, lh->vers);
    omf_set_lh_magic(lhomf, lh->magic);
    omf_set_lh_gen(lhomf, lh->gen);
    omf_set_lh_rsvd(lhomf, lh->rsvd);

    lh->crc = omf_loghdr_crc_get(lhomf);
    omf_set_lh_crc(lhomf, lh->crc);

    return 0;
}

merr_t
omf_mdc_loghdr_unpack(const char *inbuf, struct mdc_loghdr *lh)
{
    struct mdc_loghdr_omf *lhomf;
    uint32_t               crc;

    lhomf = (struct mdc_loghdr_omf *)inbuf;

    lh->vers = omf_lh_vers(lhomf);
    lh->magic = omf_lh_magic(lhomf);
    lh->gen = omf_lh_gen(lhomf);
    lh->rsvd = omf_lh_rsvd(lhomf);

    crc = omf_loghdr_crc_get(lhomf);
    lh->crc = omf_lh_crc(lhomf);
    if (crc != lh->crc) {
        const struct mdc_loghdr_omf ref = { 0 };

        return ((memcmp(lhomf, &ref, sizeof(*lhomf)) == 0) ? merr(ENODATA) : merr(ENOMSG));
    }

    return 0;
}

size_t
omf_mdc_loghdr_len(void)
{
    return sizeof(struct mdc_loghdr_omf);
}

void
omf_mdc_rechdr_unpack(const char *inbuf, struct mdc_rechdr *rh)
{
    struct mdc_rechdr_omf *rhomf;

    rhomf = (struct mdc_rechdr_omf *)inbuf;

    rh->crc = omf_rh_crc(rhomf);
    rh->rsvd = omf_rh_rsvd(rhomf);
    rh->size = omf_rh_size(rhomf);
}

size_t
omf_mdc_rechdr_len(void)
{
    return sizeof(struct mdc_rechdr_omf);
}


static uint32_t
omf_mblock_metahdr_crc_get(struct mblock_metahdr_omf *mhomf)
{
    return crc32c(0, (const uint8_t *)mhomf, offsetof(struct mblock_metahdr_omf, mh_crc));
}

void
omf_mblock_metahdr_pack(struct mblock_metahdr *mh, char *outbuf)
{
    struct mblock_metahdr_omf *mhomf;

    mhomf = (struct mblock_metahdr_omf *)outbuf;

    omf_set_mh_vers(mhomf, mh->vers);
    omf_set_mh_magic(mhomf, mh->magic);
    omf_set_mh_fszmax_gb(mhomf, mh->fszmax_gb);
    omf_set_mh_mblksz_sec(mhomf, mh->mblksz_sec);
    omf_set_mh_mcid(mhomf, mh->mcid);
    omf_set_mh_fcnt(mhomf, mh->fcnt);
    omf_set_mh_blkbits(mhomf, mh->blkbits);
    omf_set_mh_mcbits(mhomf, mh->mcbits);
    omf_set_mh_rsvd(mhomf, 0);

    omf_set_mh_crc(mhomf, omf_mblock_metahdr_crc_get(mhomf));
}

void
omf_mblock_metahdr_unpack_v1(const char *inbuf, struct mblock_metahdr *mh)
{
    struct mblock_metahdr_omf_v1 *mhomf;

    mhomf = (struct mblock_metahdr_omf_v1 *)inbuf;

    mh->fszmax_gb = omf_mh_fszmax_gb_v1(mhomf);
    mh->mblksz_sec = omf_mh_mblksz_sec_v1(mhomf);
    mh->mcid = omf_mh_mcid_v1(mhomf);
    mh->fcnt = omf_mh_fcnt_v1(mhomf);
    mh->blkbits = omf_mh_blkbits_v1(mhomf);
    mh->mcbits = omf_mh_mcbits_v1(mhomf);
}

merr_t
omf_mblock_metahdr_unpack_latest(const char *inbuf, struct mblock_metahdr *mh)
{
    struct mblock_metahdr_omf *mhomf;
    uint32_t crc;

    mhomf = (struct mblock_metahdr_omf *)inbuf;

    mh->fszmax_gb = omf_mh_fszmax_gb(mhomf);
    mh->mblksz_sec = omf_mh_mblksz_sec(mhomf);
    mh->mcid = omf_mh_mcid(mhomf);
    mh->fcnt = omf_mh_fcnt(mhomf);
    mh->blkbits = omf_mh_blkbits(mhomf);
    mh->mcbits = omf_mh_mcbits(mhomf);

    crc = omf_mblock_metahdr_crc_get(mhomf);
    if (crc != omf_mh_crc(mhomf)) {
        const struct mblock_metahdr_omf ref = { 0 };

        return ((memcmp(mhomf, &ref, sizeof(*mhomf)) == 0) ? merr(ENODATA) : merr(ENOMSG));
    }

    return 0;
}

merr_t
omf_mblock_metahdr_unpack(const void *inbuf, struct mblock_metahdr *mh)
{
    merr_t err = 0;

    mh->magic = omf_mh_magic(inbuf);

	if (mh->magic != MBLOCK_METAHDR_MAGIC) {
		bool big = (HSE_OMF_BYTE_ORDER == __ORDER_BIG_ENDIAN__);

		if (mh->magic != bswap_32(MBLOCK_METAHDR_MAGIC))
			return merr(EBADMSG);

		log_err("MDC format is %s endian, but libhse is configured to use %s endian,"
                        "try reconfiguring with -Domf-byte-order=%s",
                        big ? "little" : "big",
                        big ? "big" : "little",
                        big ? "little" : "big");

		return merr(EPROTO);
	}

    mh->vers = omf_mh_vers(inbuf);

    switch (mh->vers) {
    case MBLOCK_METAHDR_VERSION1:
        omf_mblock_metahdr_unpack_v1(inbuf, mh);
        break;

    case MBLOCK_METAHDR_VERSION:
        err = omf_mblock_metahdr_unpack_latest(inbuf, mh);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}

static uint32_t
omf_mblock_filehdr_crc_get(struct mblock_filehdr_omf *fhomf)
{
    return crc32c(0, (const uint8_t *)fhomf, offsetof(struct mblock_filehdr_omf, fh_crc));
}

void
omf_mblock_filehdr_pack(struct mblock_filehdr *fh, char *outbuf)
{
    struct mblock_filehdr_omf *fhomf;

    fhomf = (struct mblock_filehdr_omf *)outbuf;

    omf_set_fh_uniq(fhomf, fh->uniq);
    omf_set_fh_fileid(fhomf, fh->fileid);
    omf_set_fh_rsvd1(fhomf, fh->rsvd1);
    omf_set_fh_rsvd2(fhomf, fh->rsvd2);

    omf_set_fh_crc(fhomf, omf_mblock_filehdr_crc_get(fhomf));
}

static void
omf_mblock_filehdr_unpack_v1(const char *inbuf, struct mblock_filehdr *fh)
{
    struct mblock_filehdr_omf_v1 *fhomf;

    fhomf = (struct mblock_filehdr_omf_v1 *)inbuf;

    fh->uniq = omf_fh_uniq_v1(fhomf);
    fh->fileid = omf_fh_fileid_v1(fhomf);
    fh->rsvd1 = omf_fh_rsvd1_v1(fhomf);
    fh->rsvd2 = omf_fh_rsvd2_v1(fhomf);
}

static merr_t
omf_mblock_filehdr_unpack_latest(const char *inbuf, struct mblock_filehdr *fh)
{
    struct mblock_filehdr_omf *fhomf;
    uint32_t crc;

    fhomf = (struct mblock_filehdr_omf *)inbuf;

    fh->uniq = omf_fh_uniq(fhomf);
    fh->fileid = omf_fh_fileid(fhomf);
    fh->rsvd1 = omf_fh_rsvd1(fhomf);
    fh->rsvd2 = omf_fh_rsvd2(fhomf);

    crc = omf_mblock_filehdr_crc_get(fhomf);
    if (crc != omf_fh_crc(fhomf)) {
        const struct mblock_filehdr_omf ref = { 0 };

        return ((memcmp(fhomf, &ref, sizeof(*fhomf)) == 0) ? merr(ENODATA) : merr(ENOMSG));
    }

    return 0;
}

merr_t
omf_mblock_filehdr_unpack(const char *inbuf, uint32_t version, struct mblock_filehdr *fh)
{
    merr_t err = 0;

    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        omf_mblock_filehdr_unpack_v1(inbuf, fh);
        break;

    case MBLOCK_METAHDR_VERSION:
        err = omf_mblock_filehdr_unpack_latest(inbuf, fh);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}

static uint32_t
omf_mblock_oid_crc_get(struct mblock_oid_omf *mbomf)
{
    return crc32c(0, (const uint8_t *)mbomf, offsetof(struct mblock_oid_omf, mblk_crc));
}

void
omf_mblock_oid_pack(struct mblock_oid_info *mbinfo, char *outbuf)
{
    struct mblock_oid_omf *mbomf;

    mbomf = (struct mblock_oid_omf *)outbuf;

    omf_set_mblk_id(mbomf, mbinfo->mb_oid);
    omf_set_mblk_rsvd(mbomf, 0);
    omf_set_mblk_wlen(mbomf, mbinfo->mb_wlen);

    if (mbinfo->mb_oid != 0)
        omf_set_mblk_crc(mbomf, omf_mblock_oid_crc_get(mbomf));
    else
        omf_set_mblk_crc(mbomf, 0);
}

static void
omf_mblock_oid_unpack_v1(const char *inbuf, struct mblock_oid_info *mbinfo)
{
    struct mblock_oid_omf_v1 *mbomf;

    mbomf = (struct mblock_oid_omf_v1 *)inbuf;

    mbinfo->mb_oid = omf_mblk_id_v1(mbomf);
    mbinfo->mb_wlen = omf_mblk_wlen_v1(mbomf);
}

static merr_t
omf_mblock_oid_unpack_latest(const char *inbuf, struct mblock_oid_info *mbinfo)
{
    struct mblock_oid_omf *mbomf;
    uint32_t crc;

    mbomf = (struct mblock_oid_omf *)inbuf;

    mbinfo->mb_oid = omf_mblk_id(mbomf);
    mbinfo->mb_wlen = omf_mblk_wlen(mbomf);

    crc = omf_mblk_crc(mbomf);
    if (crc != 0 && (crc != omf_mblock_oid_crc_get(mbomf)))
        return merr(ENOMSG);

    return 0;
}

merr_t
omf_mblock_oid_unpack(const char *inbuf, uint32_t version, struct mblock_oid_info *mbinfo)
{
    merr_t err = 0;

    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        omf_mblock_oid_unpack_v1(inbuf, mbinfo);
        break;

    case MBLOCK_METAHDR_VERSION:
        err = omf_mblock_oid_unpack_latest(inbuf, mbinfo);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}
