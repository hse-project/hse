/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_OMF_H
#define MPOOL_OMF_H

#include <hse_util/omf.h>
#include <hse_util/hse_err.h>

#include <hse_ikvdb/omf_version.h>

struct mdc_loghdr;
struct mdc_rechdr;
struct mblock_metahdr;
struct mblock_filehdr;
struct mblock_oid_info;

/*
 * MDC OMF
 */

/**
 * struct mdc_loghdr_omf - OMF for MDC log header
 *
 * @lh_vers:  version
 * @lh_magic: magic
 * @lh_gen:   generation
 * @lh_rsvd:  reserved
 * @lh_crc:   loghdr CRC
 */
struct mdc_loghdr_omf {
    uint32_t lh_vers;
    uint32_t lh_magic;
    uint64_t lh_gen;
    uint32_t lh_rsvd;
    uint32_t lh_crc;
} HSE_PACKED;

/* Define set/get methods for mdc_loghdr_omf */
OMF_SETGET(struct mdc_loghdr_omf, lh_vers, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_magic, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_gen, 64);
OMF_SETGET(struct mdc_loghdr_omf, lh_rsvd, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_crc, 32);

/**
 * struct mdc_rechdr_omf - OMF for MDC record header
 *
 * @rh_crc:  record CRC
 * @rh_rsvd: reserved
 * @rh_size: record length
 * @rh_data: record
 */
struct mdc_rechdr_omf {
    uint32_t rh_crc;
    uint32_t rh_rsvd;
    uint64_t rh_size;
    uint8_t  rh_data[0];
} __attribute__((packed,aligned(sizeof(uint64_t))));

/* Define set/get methods for mdc_rechdr_omf */
OMF_SETGET(struct mdc_rechdr_omf, rh_crc, 32);
OMF_SETGET(struct mdc_rechdr_omf, rh_rsvd, 32);
OMF_SETGET(struct mdc_rechdr_omf, rh_size, 64);

/**
 * omf_mdc_loghdr_pack - Pack lh into outbuf
 *
 * @lh:     in-memory log header
 * @outbuf: packed log header (output)
 */
merr_t
omf_mdc_loghdr_pack(struct mdc_loghdr *lh, char *outbuf);

/**
 * omf_mdc_loghdr_unpack - Unpack inbuf into lh
 *
 * @inbuf: packed log header
 * @lh:    unpacked in-memory log header (output)
 */
merr_t
omf_mdc_loghdr_unpack(const char *inbuf, struct mdc_loghdr *lh);

/**
 * omf_mdc_loghdr_len - return log header length
 */
size_t
omf_mdc_loghdr_len(void);

/**
 * omf_mdc_rechdr_unpack - Unpack inbuf into rh
 *
 * @inbuf: packed log header
 * @rh:    unpacked in-memory record header (output)
 */
void
omf_mdc_rechdr_unpack(const char *inbuf, struct mdc_rechdr *rh);

/**
 * omf_mdc_rechdr_len - return record header length
 */
size_t
omf_mdc_rechdr_len(void);

/*
 * Mblock Meta OMF
 */

/**
 * struct mblock_metahdr_omf_v1 - mblock fset meta header (version 1)
 */
struct mblock_metahdr_omf_v1 {
    uint32_t mh_vers;
    uint32_t mh_magic;
    uint32_t mh_fszmax_gb;
    uint32_t mh_mblksz_sec;
    uint8_t  mh_mcid;
    uint8_t  mh_fcnt;
    uint8_t  mh_blkbits;
    uint8_t  mh_mcbits;
} HSE_PACKED;

/* Define set/get methods for mblock_metahdr_omf_v1 */
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_vers, 32, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_magic, 32, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_fszmax_gb, 32, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_mblksz_sec, 32, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_mcid, 8, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_fcnt, 8, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_blkbits, 8, v1);
OMF_GET_VER(struct mblock_metahdr_omf_v1, mh_mcbits, 8, v1);

/**
 * struct mblock_metahdr_omf - mblock fset meta header
 *
 * @mh_vers:       version
 * @mh_magic:      magic
 * @mh_fszmax_gb:  max file size
 * @mh_mblksz_sec: mblock size
 * @mh_mcid:       media class ID
 * @mh_fcnt:       file count
 * @mh_blkbits:    no. of bits used for block offset
 * @mh_mcbits:     no. of media class bits
 * @mh_rsvd:       reserved
 * @mh_crc:        meta header crc
 * @mh_gclose:     records whether the previous open of this mclass was gracefully closed
 */
struct mblock_metahdr_omf {
    uint32_t mh_vers;
    uint32_t mh_magic;
    uint32_t mh_fszmax_gb;
    uint32_t mh_mblksz_sec;
    uint8_t  mh_mcid;
    uint8_t  mh_fcnt;
    uint8_t  mh_blkbits;
    uint8_t  mh_mcbits;
    uint32_t mh_rsvd;
    uint32_t mh_crc;
    uint32_t mh_gclose;
} HSE_PACKED;

/* Define set/get methods for mblock_metahdr_omf */
OMF_SETGET(struct mblock_metahdr_omf, mh_vers, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_magic, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_fszmax_gb, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_mblksz_sec, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_mcid, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_fcnt, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_blkbits, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_mcbits, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_rsvd, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_crc, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_gclose, 32);

/**
 * struct mblock_filehdr_omf_v1 - mblock file meta header (version 1)
 */
struct mblock_filehdr_omf_v1 {
    uint32_t fh_uniq;
    uint8_t  fh_fileid;
    uint8_t  fh_rsvd1;
    uint16_t fh_rsvd2;
} HSE_PACKED;

/* Define set/get methods for mblock_filehdr_omf_v1 */
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_uniq, 32, v1);
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_fileid, 8, v1);
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_rsvd1, 8, v1);
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_rsvd2, 16, v1);

/**
 * struct mblock_filehdr_omf - mblock file meta header
 *
 * @fh_uniq:   uniquifier
 * @fh_fileid: file id
 * @fh_rsvd1:  reserved 1
 * @fh_rsvd2:  reserved 2
 * @fh_crc:    fh crc
 */
struct mblock_filehdr_omf {
    uint32_t fh_uniq;
    uint8_t  fh_fileid;
    uint8_t  fh_rsvd1;
    uint16_t fh_rsvd2;
    uint32_t fh_crc;
} HSE_PACKED;

/* Define set/get methods for mblock_filehdr_omf */
OMF_SETGET(struct mblock_filehdr_omf, fh_uniq, 32);
OMF_SETGET(struct mblock_filehdr_omf, fh_fileid, 8);
OMF_SETGET(struct mblock_filehdr_omf, fh_rsvd1, 8);
OMF_SETGET(struct mblock_filehdr_omf, fh_rsvd2, 16);
OMF_SETGET(struct mblock_filehdr_omf, fh_crc, 32);

/**
 * struct mblock_oid_omf_v1 - per mblock OMF (version 1)
 */
struct mblock_oid_omf_v1 {
    uint64_t mblk_id;
    uint32_t mblk_wlen;
    uint32_t mblk_rsvd1;
    uint64_t mblk_rsvd2;
} HSE_PACKED;

/* Define set/get methods for mblock_oid_omf_v1 */
OMF_GET_VER(struct mblock_oid_omf_v1, mblk_id, 64, v1);
OMF_GET_VER(struct mblock_oid_omf_v1, mblk_wlen, 32, v1);
OMF_GET_VER(struct mblock_oid_omf_v1, mblk_rsvd1, 32, v1);
OMF_GET_VER(struct mblock_oid_omf_v1, mblk_rsvd2, 64, v1);

#define MBLOCK_FILE_META_OIDLEN_V1 (sizeof(struct mblock_oid_omf_v1))

/**
 * struct mblock_oid_omf - per mblock OMF
 *
 * @mblk_id:   mblock ID
 * @mblk_rsvd: reserved
 * @mblk_wlen: mblock write length
 * @mblk_crc:  crc
 */
struct mblock_oid_omf {
    uint64_t mblk_id;
    uint64_t mblk_rsvd;
    uint32_t mblk_wlen;
    uint32_t mblk_crc;
} HSE_PACKED;

/* Define set/get methods for mblock_oid_omf */
OMF_SETGET(struct mblock_oid_omf, mblk_id, 64);
OMF_SETGET(struct mblock_oid_omf, mblk_rsvd, 64);
OMF_SETGET(struct mblock_oid_omf, mblk_wlen, 32);
OMF_SETGET(struct mblock_oid_omf, mblk_crc, 32);

#define MBLOCK_FILE_META_OIDLEN (sizeof(struct mblock_oid_omf))

static HSE_ALWAYS_INLINE uint32_t
omf_mblock_oid_len(uint32_t version)
{
    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        return MBLOCK_FILE_META_OIDLEN_V1;

    case MBLOCK_METAHDR_VERSION:
        return MBLOCK_FILE_META_OIDLEN;

    default:
        abort();
    }
}

/**
 * omf_mblock_metahdr_pack -
 *
 * @mh:     in-memory mblock meta header
 * @outbuf: packed mblock meta header (output)
 */
void
omf_mblock_metahdr_pack(struct mblock_metahdr *mh, char *outbuf);

/**
 * omf_mblock_metahdr_unpack -
 *
 * @inbuf: packed mblock meta header
 * @mh:    unpacked mblock meta header (output)
 */
merr_t
omf_mblock_metahdr_unpack(const void *inbuf, struct mblock_metahdr *mh);

/**
 * omf_mblock_filehdr_pack -
 *
 * @fh:     in-memory mblock file meta header
 * @outbuf: packed mblock file meta header (output)
 */
void
omf_mblock_filehdr_pack(struct mblock_filehdr *fh, char *outbuf);

/**
 * omf_mblock_filehdr_unpack -
 *
 * @inbuf:   packed mblock file meta header
 * @version: mblock meta header on-media version
 * @mh:      unpacked mblock file meta header (output)
 */
merr_t
omf_mblock_filehdr_unpack(const char *inbuf, uint32_t version, struct mblock_filehdr *fh);

/**
 * omf_mblock_oid_pack -
 *
 * @mbinfo: in-memory mblock oid info
 * @outbuf: packed mblock oid meta (output)
 */
void
omf_mblock_oid_pack(struct mblock_oid_info *mbinfo, char *outbuf);

/**
 * omf_mblock_oid_unpack -
 *
 * @inbuf:   packed mblock oid meta
 * @version: mblock meta header on-media version
 * @mbinfo:  unpacked mblock oid info (output)
 */
merr_t
omf_mblock_oid_unpack(const char *inbuf, uint32_t version, struct mblock_oid_info *mbinfo);

#endif /* MPOOL_OMF_H */
