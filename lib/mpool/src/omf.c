/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <crc32c/crc32c.h>
#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>

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
omf_mdc_loghdr_pack_htole(struct mdc_loghdr *lh, char *outbuf)
{
    struct mdc_loghdr_omf *lhomf;

    lhomf = (struct mdc_loghdr_omf *)outbuf;

    if (ev(lh->vers != MDC_LOGHDR_VERSION))
        return merr(EINVAL);

    omf_set_lh_vers(lhomf, lh->vers);
    omf_set_lh_magic(lhomf, lh->magic);
    omf_set_lh_rsvd(lhomf, lh->rsvd);
    omf_set_lh_gen(lhomf, lh->gen);

    lh->crc = omf_loghdr_crc_get(lhomf);
    omf_set_lh_crc(lhomf, lh->crc);

    return 0;
}

merr_t
omf_mdc_loghdr_unpack_letoh(struct mdc_loghdr *lh, const char *inbuf)
{
    struct mdc_loghdr_omf *lhomf;
    uint32_t               crc;

    lhomf = (struct mdc_loghdr_omf *)inbuf;

    crc = omf_loghdr_crc_get(lhomf);
    lh->crc = omf_lh_crc(lhomf);
    if (crc != lh->crc)
        return merr(EBADMSG);

    lh->vers = omf_lh_vers(lhomf);
    lh->magic = omf_lh_magic(lhomf);
    lh->rsvd = omf_lh_rsvd(lhomf);
    lh->gen = omf_lh_gen(lhomf);

    return 0;
}

size_t
omf_mdc_loghdr_len(void)
{
    return sizeof(struct mdc_loghdr_omf);
}

void
omf_mdc_rechdr_unpack_letoh(struct mdc_rechdr *rh, const char *inbuf)
{
    struct mdc_rechdr_omf *rhomf;

    rhomf = (struct mdc_rechdr_omf *)inbuf;

    rh->crc = omf_rh_crc(rhomf);
    rh->size = omf_rh_size(rhomf);
}

size_t
omf_mdc_rechdr_len(void)
{
    return sizeof(struct mdc_rechdr_omf);
}

void
omf_mblock_metahdr_pack_htole(struct mblock_metahdr *mh, char *outbuf)
{
    struct mblock_metahdr_omf *mhomf;

    mhomf = (struct mblock_metahdr_omf *)outbuf;

    omf_set_mh_vers(mhomf, mh->vers);
    omf_set_mh_magic(mhomf, mh->magic);
    omf_set_mh_fszmax_gb(mhomf, mh->fszmax_gb);
    omf_set_mh_mblksz_mb(mhomf, mh->mblksz_mb);
    omf_set_mh_mcid(mhomf, mh->mcid);
    omf_set_mh_fcnt(mhomf, mh->fcnt);
    omf_set_mh_blkbits(mhomf, mh->blkbits);
    omf_set_mh_mcbits(mhomf, mh->mcbits);
}

void
omf_mblock_metahdr_unpack_letoh(struct mblock_metahdr *mh, const char *inbuf)
{
    struct mblock_metahdr_omf *mhomf;

    mhomf = (struct mblock_metahdr_omf *)inbuf;

    mh->vers = omf_mh_vers(mhomf);
    mh->magic = omf_mh_magic(mhomf);
    mh->fszmax_gb = omf_mh_fszmax_gb(mhomf);
    mh->mblksz_mb = omf_mh_mblksz_mb(mhomf);
    mh->mcid = omf_mh_mcid(mhomf);
    mh->fcnt = omf_mh_fcnt(mhomf);
    mh->blkbits = omf_mh_blkbits(mhomf);
    mh->mcbits = omf_mh_mcbits(mhomf);
}

void
omf_mblock_filehdr_pack_htole(struct mblock_filehdr *fh, char *outbuf)
{
    struct mblock_filehdr_omf *fhomf;

    fhomf = (struct mblock_filehdr_omf *)outbuf;

    omf_set_fh_uniq(fhomf, fh->uniq);
    omf_set_fh_fileid(fhomf, fh->fileid);
    omf_set_fh_rsvd1(fhomf, fh->rsvd1);
    omf_set_fh_rsvd2(fhomf, fh->rsvd2);
}

void
omf_mblock_filehdr_unpack_letoh(struct mblock_filehdr *fh, const char *inbuf)
{
    struct mblock_filehdr_omf *fhomf;

    fhomf = (struct mblock_filehdr_omf *)inbuf;

    fh->uniq = omf_fh_uniq(fhomf);
    fh->fileid = omf_fh_fileid(fhomf);
    fh->rsvd1 = omf_fh_rsvd1(fhomf);
    fh->rsvd2 = omf_fh_rsvd2(fhomf);
}
