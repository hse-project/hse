/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/page.h>

#include "omf.h"
#include "mblock_file.h"
#include "mblock_fset.h"
#include "mdc_file.h"

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

/*
 * MDC Log Header Routines
 */
static uint32_t
omf_loghdr_crc_get(struct mdc_loghdr_omf *lhomf)
{
    return crc32c(0, (const uint8_t *)lhomf, offsetof(struct mdc_loghdr_omf, lh_crc));
}

merr_t
omf_mdc_loghdr_pack(struct mdc_loghdr *lh, char *outbuf)
{
    struct mdc_loghdr_omf *lhomf;
    uint64_t crc;

    lhomf = (struct mdc_loghdr_omf *)outbuf;

    if (lh->vers != MDC_LOGHDR_VERSION)
        return merr(EINVAL);

    omf_set_lh_vers(lhomf, lh->vers);
    omf_set_lh_magic(lhomf, lh->magic);
    omf_set_lh_gen(lhomf, lh->gen);

    lh->crc = omf_loghdr_crc_get(lhomf);
    crc = crc_valid_bit_set(lh->crc);

    omf_set_lh_crc(lhomf, crc);

    return 0;
}

static uint32_t
omf_loghdr_crc_get_v1(struct mdc_loghdr_omf_v1 *lhomf)
{
    return crc32c(0, (const uint8_t *)lhomf, offsetof(struct mdc_loghdr_omf_v1, lh_crc));
}

static merr_t
omf_mdc_loghdr_unpack_v1(const char *inbuf, struct mdc_loghdr *lh)
{
    struct mdc_loghdr_omf_v1 *lhomf;
    uint32_t                  crc;

    lhomf = (struct mdc_loghdr_omf_v1 *)inbuf;

    crc = omf_loghdr_crc_get_v1(lhomf);
    lh->crc = omf_lh_crc_v1(lhomf);
    if (crc != lh->crc)
        return merr(EBADMSG);

    lh->magic = omf_lh_magic_v1(lhomf);
    lh->gen = omf_lh_gen_v1(lhomf);

    return 0;
}

static merr_t
omf_mdc_loghdr_unpack_latest(const char *inbuf, bool gclose, struct mdc_loghdr *lh)
{
    struct mdc_loghdr_omf *lhomf;
    uint64_t               crc;
    uint32_t               crc32;

    lhomf = (struct mdc_loghdr_omf *)inbuf;

    lh->magic = omf_lh_magic(lhomf);
    lh->gen = omf_lh_gen(lhomf);

    crc = omf_lh_crc(lhomf);
    crc32 = omf_loghdr_crc_get(lhomf);
    lh->crc = crc & CRC_MASK;
    if ((crc32 != lh->crc) || !crc_valid_bit_isset(crc))
        return (gclose ? merr(EBADMSG) : merr(ENOMSG));

    return 0;
}

merr_t
omf_mdc_loghdr_unpack(const void *inbuf, bool gclose, struct mdc_loghdr *lh)
{
    const struct mdc_loghdr_omf ref = { 0 };
    merr_t err;

    lh->vers = omf_lh_vers(inbuf);
    if (lh->vers == 0 && (memcmp(inbuf, &ref, sizeof(ref)) == 0))
        return merr(ENODATA);

    switch (lh->vers) {
    case MDC_LOGHDR_VERSION1:
        err = omf_mdc_loghdr_unpack_v1(inbuf, lh);
        break;

    case MDC_LOGHDR_VERSION:
        err = omf_mdc_loghdr_unpack_latest(inbuf, gclose, lh);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}

/*
 * MDC Record Header Routines
 */

static uint32_t
omf_rechdr_crc_get(const uint8_t *data1, size_t len1, const uint8_t *data2, size_t len2)
{
    uint32_t crc = crc32c(0, data1, len1);

    return crc32c(crc, data2, len2);
}

void
omf_mdc_rechdr_pack(void *data, size_t len, void *outbuf)
{
    struct mdc_rechdr_omf *rhomf = outbuf;
    uint64_t crc;
    uint32_t crc32;
    uint8_t hdrlen;

    omf_set_rh_size(rhomf, len);

    hdrlen = sizeof(rhomf->rh_size);
    crc32 = omf_rechdr_crc_get((const uint8_t *)&rhomf->rh_size, hdrlen, data, len);
    crc = crc_valid_bit_set(crc32);
    omf_set_rh_crc(rhomf, crc);
}

static merr_t
omf_mdc_rechdr_unpack_v1(const char *inbuf, bool crc_verify, struct mdc_rechdr *rh)
{
    struct mdc_rechdr_omf_v1 *rhomf;
    uint32_t crc;

    rhomf = (struct mdc_rechdr_omf_v1 *)inbuf;

    rh->crc = omf_rh_crc_v1(rhomf);
    rh->size = omf_rh_size_v1(rhomf);

    if (crc_verify) {
        uint8_t hdrlen = sizeof(rhomf->rh_size);
        const char *data;

        data = inbuf + omf_mdc_rechdr_len(MDC_LOGHDR_VERSION1);

        crc = omf_rechdr_crc_get((const uint8_t *)&rhomf->rh_size, hdrlen,
                                 (const uint8_t *)data, rh->size);
        if (crc != rh->crc) {
            const struct mdc_rechdr_omf ref = { 0 };

            return ((memcmp(rhomf, &ref, sizeof(*rhomf)) == 0) ? merr(ENODATA) : merr(ENOMSG));
        }
    }

    return 0;
}

static merr_t
omf_mdc_rechdr_unpack_latest(const char *inbuf, bool gclose, bool crc_verify, struct mdc_rechdr *rh)
{
    struct mdc_rechdr_omf *rhomf;
    uint64_t crc;
    uint32_t crc32;

    rhomf = (struct mdc_rechdr_omf *)inbuf;

    crc = omf_rh_crc(rhomf);
    rh->crc = crc & CRC_MASK;
    rh->size = omf_rh_size(rhomf);

    if (crc_verify) {
        uint8_t hdrlen = sizeof(rhomf->rh_size);

        crc32 = omf_rechdr_crc_get((const uint8_t *)&rhomf->rh_size, hdrlen,
                                   (const uint8_t *)rhomf->rh_data, rh->size);
        if (crc32 != rh->crc || !crc_valid_bit_isset(crc)) {
            const struct mdc_rechdr_omf ref = { 0 };

            return ((memcmp(rhomf, &ref, sizeof(*rhomf)) == 0) ? merr(ENODATA) :
                    (gclose ? merr(EBADMSG) : merr(ENOMSG)));
        }
    }

    return 0;
}

merr_t
omf_mdc_rechdr_unpack(
    const char        *inbuf,
    uint32_t           version,
    bool               gclose,
    bool               crc_verify,
    struct mdc_rechdr *rh)
{
    merr_t err = 0;

    switch (version) {
    case MDC_LOGHDR_VERSION1:
        err = omf_mdc_rechdr_unpack_v1(inbuf, crc_verify, rh);
        break;

    case MDC_LOGHDR_VERSION:
        err = omf_mdc_rechdr_unpack_latest(inbuf, gclose, crc_verify, rh);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}

/*
 * Mblock Meta Header Routines
 */
static uint32_t
omf_mblock_metahdr_crc_get(struct mblock_metahdr_omf *mhomf)
{
    return crc32c(0, (const uint8_t *)mhomf, offsetof(struct mblock_metahdr_omf, mh_crc));
}

void
omf_mblock_metahdr_pack(struct mblock_metahdr *mh, char *outbuf)
{
    struct mblock_metahdr_omf *mhomf;
    uint64_t crc;
    uint32_t crc32;

    mhomf = (struct mblock_metahdr_omf *)outbuf;

    omf_set_mh_vers(mhomf, mh->vers);
    omf_set_mh_magic(mhomf, mh->magic);
    omf_set_mh_fszmax_gb(mhomf, mh->fszmax >> GB_SHIFT);
    omf_set_mh_mblksz_sec(mhomf, mh->mblksz >> SECTOR_SHIFT);
    omf_set_mh_mcid(mhomf, mh->mcid);
    omf_set_mh_fcnt(mhomf, mh->fcnt);
    omf_set_mh_blkbits(mhomf, mh->blkbits);
    omf_set_mh_mcbits(mhomf, mh->mcbits);

    crc32 = omf_mblock_metahdr_crc_get(mhomf);
    crc = crc_valid_bit_set(crc32);
    omf_set_mh_crc(mhomf, crc);

    omf_set_mh_gclose(mhomf, mh->gclose ? 1 : 0);
}

void
omf_mblock_metahdr_gclose_set(char *outbuf, bool gclose)
{
    struct mblock_metahdr_omf *mhomf;

    mhomf = (struct mblock_metahdr_omf *)outbuf;

    omf_set_mh_gclose(mhomf, gclose ? 1 : 0);
}

void
omf_mblock_metahdr_unpack_v1(const char *inbuf, struct mblock_metahdr *mh)
{
    struct mblock_metahdr_omf_v1 *mhomf;

    mhomf = (struct mblock_metahdr_omf_v1 *)inbuf;

    mh->fszmax = ((uint64_t)omf_mh_fszmax_gb_v1(mhomf)) << GB_SHIFT;
    mh->mblksz = ((uint64_t)omf_mh_mblksz_sec_v1(mhomf)) << SECTOR_SHIFT;
    mh->mcid = omf_mh_mcid_v1(mhomf);
    mh->fcnt = omf_mh_fcnt_v1(mhomf);
    mh->blkbits = omf_mh_blkbits_v1(mhomf);
    mh->mcbits = omf_mh_mcbits_v1(mhomf);
}

merr_t
omf_mblock_metahdr_unpack_latest(const char *inbuf, struct mblock_metahdr *mh)
{
    struct mblock_metahdr_omf *mhomf;
    uint64_t crc;
    uint32_t crc32;

    mhomf = (struct mblock_metahdr_omf *)inbuf;

    mh->fszmax = ((uint64_t)omf_mh_fszmax_gb(mhomf)) << GB_SHIFT;
    mh->mblksz = ((uint64_t)omf_mh_mblksz_sec(mhomf)) << SECTOR_SHIFT;
    mh->mcid = omf_mh_mcid(mhomf);
    mh->fcnt = omf_mh_fcnt(mhomf);
    mh->blkbits = omf_mh_blkbits(mhomf);
    mh->mcbits = omf_mh_mcbits(mhomf);
    mh->gclose = (omf_mh_gclose(mhomf) == 1);

    crc = omf_mh_crc(mhomf);
    crc32 = omf_mblock_metahdr_crc_get(mhomf);
    if ((crc32 != (crc & CRC_MASK)) || !crc_valid_bit_isset(crc)) {
        const struct mblock_metahdr_omf ref = { 0 };

        return ((memcmp(mhomf, &ref, sizeof(*mhomf)) == 0) ? merr(ENODATA) :
                (mh->gclose ? merr(EBADMSG) : merr(ENOMSG)));
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

/*
 * Mblock File Header Routines
 */
static uint32_t
omf_mblock_filehdr_crc_get(struct mblock_filehdr_omf *fhomf)
{
    return crc32c(0, (const uint8_t *)fhomf, offsetof(struct mblock_filehdr_omf, fh_crc));
}

void
omf_mblock_filehdr_pack(struct mblock_filehdr *fh, char *outbuf)
{
    struct mblock_filehdr_omf *fhomf;
    uint64_t crc;
    uint32_t crc32;

    fhomf = (struct mblock_filehdr_omf *)outbuf;

    omf_set_fh_uniq(fhomf, fh->uniq);
    omf_set_fh_fileid(fhomf, fh->fileid);
    omf_set_fh_rsvd1(fhomf, 0);
    omf_set_fh_rsvd2(fhomf, 0);

    crc32 = omf_mblock_filehdr_crc_get(fhomf);
    crc = crc_valid_bit_set(crc32);
    omf_set_fh_crc(fhomf, crc);
}

static void
omf_mblock_filehdr_unpack_v1(const char *inbuf, struct mblock_filehdr *fh)
{
    struct mblock_filehdr_omf_v1 *fhomf;

    fhomf = (struct mblock_filehdr_omf_v1 *)inbuf;

    fh->uniq = omf_fh_uniq_v1(fhomf);
    fh->fileid = omf_fh_fileid_v1(fhomf);
}

static merr_t
omf_mblock_filehdr_unpack_latest(const char *inbuf, bool gclose, struct mblock_filehdr *fh)
{
    struct mblock_filehdr_omf *fhomf;
    uint64_t crc;
    uint32_t crc32;

    fhomf = (struct mblock_filehdr_omf *)inbuf;

    fh->uniq = omf_fh_uniq(fhomf);
    fh->fileid = omf_fh_fileid(fhomf);

    crc = omf_fh_crc(fhomf);
    crc32 = omf_mblock_filehdr_crc_get(fhomf);
    if ((crc32 != (crc & CRC_MASK)) || !crc_valid_bit_isset(crc)) {
        const struct mblock_filehdr_omf ref = { 0 };

        return ((memcmp(fhomf, &ref, sizeof(*fhomf)) == 0) ? merr(ENODATA) :
                (gclose ? merr(EBADMSG) : merr(ENOMSG)));
    }

    return 0;
}

merr_t
omf_mblock_filehdr_unpack(
    const char            *inbuf,
    uint32_t               version,
    bool                   gclose,
    struct mblock_filehdr *fh)
{
    merr_t err = 0;

    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        omf_mblock_filehdr_unpack_v1(inbuf, fh);
        break;

    case MBLOCK_METAHDR_VERSION:
        err = omf_mblock_filehdr_unpack_latest(inbuf, gclose, fh);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}

/*
 * Mblock OID meta Routines
 */
static uint32_t
omf_mblock_oid_crc_get(struct mblock_oid_omf *mbomf)
{
    return crc32c(0, (const uint8_t *)mbomf, offsetof(struct mblock_oid_omf, mblk_crc));
}

void
omf_mblock_oid_pack(struct mblock_oid_info *mbinfo, char *outbuf)
{
    struct mblock_oid_omf *mbomf;
    uint64_t crc;
    uint32_t crc32;

    assert(mbinfo->mb_oid != 0);

    mbomf = (struct mblock_oid_omf *)outbuf;

    omf_set_mblk_id(mbomf, mbinfo->mb_oid);
    omf_set_mblk_rsvd1(mbomf, 0);
    omf_set_mblk_rsvd2(mbomf, 0);
    omf_set_mblk_wlen(mbomf, mbinfo->mb_wlen);

    crc32 = omf_mblock_oid_crc_get(mbomf);
    crc = crc_valid_bit_set(crc32);
    omf_set_mblk_crc(mbomf, crc);
}

void
omf_mblock_oid_pack_zero(char *outbuf)
{
    struct mblock_oid_omf *mbomf;

    mbomf = (struct mblock_oid_omf *)outbuf;

    omf_set_mblk_id(mbomf, 0);
    omf_set_mblk_rsvd1(mbomf, 0);
    omf_set_mblk_rsvd2(mbomf, 0);
    omf_set_mblk_wlen(mbomf, 0);
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
omf_mblock_oid_unpack_latest(const char *inbuf, bool gclose, struct mblock_oid_info *mbinfo)
{
    struct mblock_oid_omf *mbomf;
    uint64_t crc;
    uint32_t crc32;

    mbomf = (struct mblock_oid_omf *)inbuf;

    mbinfo->mb_oid = omf_mblk_id(mbomf);
    mbinfo->mb_wlen = omf_mblk_wlen(mbomf);

    crc = omf_mblk_crc(mbomf);
    crc32 = omf_mblock_oid_crc_get(mbomf);
    if ((crc32 != (crc & CRC_MASK)) || !crc_valid_bit_isset(crc)) {
        const struct mblock_oid_omf ref = { 0 };

        return ((memcmp(mbomf, &ref, sizeof(*mbomf)) == 0) ? 0 :
                (gclose ? merr(EBADMSG) : merr(ENOMSG)));
    }

    return 0;
}

merr_t
omf_mblock_oid_unpack(
    const char             *inbuf,
    uint32_t                version,
    bool                    gclose,
    struct mblock_oid_info *mbinfo)
{
    merr_t err = 0;

    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        omf_mblock_oid_unpack_v1(inbuf, mbinfo);
        break;

    case MBLOCK_METAHDR_VERSION:
        err = omf_mblock_oid_unpack_latest(inbuf, gclose, mbinfo);
        break;

    default:
        err = merr(EPROTO);
        break;
    }

    return err;
}
