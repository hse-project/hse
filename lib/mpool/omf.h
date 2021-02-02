/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_OMF_H
#define MPOOL_OMF_H

#include <hse_util/omf.h>
#include <hse_util/hse_err.h>

#include "mdc_file.h"

/*
 * MDC OMF
 */


struct mdc_loghdr_omf {
	__le32 lh_vers;
	__le32 lh_magic;
	__le32 lh_rsvd;
	__le64 lh_gen;
	__le32 lh_crc;
} __packed;

/* Define set/get methods for mdc_loghdr_omf */
OMF_SETGET(struct mdc_loghdr_omf, lh_vers, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_magic, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_rsvd, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_gen, 64);
OMF_SETGET(struct mdc_loghdr_omf, lh_crc, 32);


struct mdc_rechdr_omf {
	__le32 rh_crc;
	__le64 rh_size;
} __packed;

/* Define set/get methods for mdc_rechdr_omf */
OMF_SETGET(struct mdc_rechdr_omf, rh_crc, 32);
OMF_SETGET(struct mdc_rechdr_omf, rh_size, 64);

merr_t
omf_mdc_loghdr_pack_htole(struct mdc_loghdr *lh, char *outbuf);

merr_t
omf_mdc_loghdr_unpack_letoh(struct mdc_loghdr *lh, const char *inbuf);

size_t
omf_mdc_loghdr_len(void);

void
omf_mdc_rechdr_unpack_letoh(struct mdc_rechdr *rh, const char *inbuf);

size_t
omf_mdc_rechdr_len(void);

#endif /* MPOOL_OMF_H */
