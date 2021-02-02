/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <3rdparty/crc32c.h>
#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>

#include "omf.h"

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
    uint32_t crc;

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
