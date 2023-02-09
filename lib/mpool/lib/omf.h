/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef MPOOL_OMF_H
#define MPOOL_OMF_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <hse/error/merr.h>
#include <hse/ikvdb/omf_version.h>
#include <hse/util/omf.h>

struct mdc_loghdr;
struct mdc_rechdr;
struct mblock_metahdr;
struct mblock_filehdr;
struct mblock_oid_info;

#define CRC_VALID_SHIFT (32)
#define CRC_VALID_MASK  (0x0000000100000000)
#define CRC_MASK        (0x00000000ffffffff)

/*
 * MDC OMF
 */

/**
 * struct mdc_loghdr_omf_v1 - OMF for MDC log header version 1
 *
 * @lh_vers:  version
 * @lh_magic: magic
 * @lh_gen:   generation
 * @lh_rsvd:  reserved
 * @lh_crc:   loghdr CRC
 */
struct mdc_loghdr_omf_v1 {
    uint32_t lh_vers;
    uint32_t lh_magic;
    uint64_t lh_gen;
    uint32_t lh_rsvd;
    uint32_t lh_crc;
} HSE_PACKED;

/* Define set/get methods for mdc_loghdr_omf_v1 */
OMF_GET_VER(struct mdc_loghdr_omf_v1, lh_vers, 32, v1);
OMF_GET_VER(struct mdc_loghdr_omf_v1, lh_magic, 32, v1);
OMF_GET_VER(struct mdc_loghdr_omf_v1, lh_gen, 64, v1);
OMF_GET_VER(struct mdc_loghdr_omf_v1, lh_rsvd, 32, v1);
OMF_GET_VER(struct mdc_loghdr_omf_v1, lh_crc, 32, v1);

#define MDC_LOGHDR_OMFLEN_V1 (sizeof(struct mdc_loghdr_omf_v1))

/**
 * struct mdc_loghdr_omf - OMF for MDC log header
 *
 * @lh_vers:  version
 * @lh_magic: magic
 * @lh_gen:   generation
 * @lh_crc:   loghdr CRC
 */
struct mdc_loghdr_omf {
    uint32_t lh_vers;
    uint32_t lh_magic;
    uint64_t lh_gen;
    uint64_t lh_crc;
} HSE_PACKED;

/* Define set/get methods for mdc_loghdr_omf */
OMF_SETGET(struct mdc_loghdr_omf, lh_vers, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_magic, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_gen, 64);
OMF_SETGET(struct mdc_loghdr_omf, lh_crc, 64);

#define MDC_LOGHDR_OMFLEN (sizeof(struct mdc_loghdr_omf))

static HSE_ALWAYS_INLINE uint32_t
omf_mdc_loghdr_len(uint32_t version)
{
    switch (version) {
    case MDC_LOGHDR_VERSION1:
        return MDC_LOGHDR_OMFLEN_V1;

    case MDC_LOGHDR_VERSION:
        return MDC_LOGHDR_OMFLEN;

    default:
        abort();
    }
}

/**
 * struct mdc_rechdr_omf_v1 - OMF for MDC record header
 *
 * @rh_crc:  record CRC
 * @rh_rsvd: reserved
 * @rh_size: record length
 */
struct mdc_rechdr_omf_v1 {
    uint32_t rh_crc;
    uint32_t rh_rsvd;
    uint64_t rh_size;
} HSE_PACKED;

/* Define set/get methods for mdc_rechdr_omf_v1 */
OMF_GET_VER(struct mdc_rechdr_omf_v1, rh_crc, 32, v1);
OMF_GET_VER(struct mdc_rechdr_omf_v1, rh_rsvd, 32, v1);
OMF_GET_VER(struct mdc_rechdr_omf_v1, rh_size, 64, v1);

#define MDC_RECHDR_LEN_V1 (sizeof(struct mdc_rechdr_omf_v1))

/**
 * struct mdc_rechdr_omf - OMF for MDC record header
 *
 * @rh_crc:  record CRC
 * @rh_rsvd: reserved
 * @rh_size: record length
 * @rh_data: record
 */
struct mdc_rechdr_omf {
    uint64_t rh_crc;
    uint64_t rh_size;
    uint8_t rh_data[0];
} __attribute__((packed, aligned(sizeof(uint64_t))));

/* Define set/get methods for mdc_rechdr_omf */
OMF_SETGET(struct mdc_rechdr_omf, rh_crc, 64);
OMF_SETGET(struct mdc_rechdr_omf, rh_size, 64);

#define MDC_RECHDR_LEN (sizeof(struct mdc_rechdr_omf))

static HSE_ALWAYS_INLINE uint32_t
omf_mdc_rechdr_len(uint32_t version)
{
    switch (version) {
    case MDC_LOGHDR_VERSION1:
        return MDC_RECHDR_LEN_V1;

    case MDC_LOGHDR_VERSION:
        return MDC_RECHDR_LEN;

    default:
        abort();
    }
}

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
 * @inbuf:  packed log header
 * @gclose: graceful close
 * @lh :    unpacked in-memory log header (output)
 */
merr_t
omf_mdc_loghdr_unpack(const void *inbuf, bool gclose, struct mdc_loghdr *lh);

void
omf_mdc_rechdr_pack(void *data, size_t len, void *outbuf);

/**
 * omf_mdc_rechdr_unpack - Unpack inbuf into rh
 *
 * @inbuf:      packed log header
 * @version:    record header version
 * @curoff:     current record offset
 * @len:        mdc file length
 * @gclose:     graceful close
 * @crc_verify: verify crc?
 * @rh:         unpacked in-memory record header (output)
 */
merr_t
omf_mdc_rechdr_unpack(
    const char *inbuf,
    uint32_t version,
    off_t curoff,
    size_t len,
    bool gclose,
    bool crc_verify,
    struct mdc_rechdr *rh);
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
    uint8_t mh_mcid;
    uint8_t mh_fcnt;
    uint8_t mh_blkbits;
    uint8_t mh_mcbits;
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

#define MBLOCK_METAHDR_LEN_V1 (sizeof(struct mblock_metahdr_omf_v1))

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
    uint8_t mh_mcid;
    uint8_t mh_fcnt;
    uint8_t mh_blkbits;
    uint8_t mh_mcbits;
    uint64_t mh_crc;
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
OMF_SETGET(struct mblock_metahdr_omf, mh_crc, 64);
OMF_SETGET(struct mblock_metahdr_omf, mh_gclose, 32);

#define MBLOCK_METAHDR_LEN (sizeof(struct mblock_metahdr_omf))

static HSE_ALWAYS_INLINE uint32_t
omf_mblock_metahdr_len(uint32_t version)
{
    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        return MBLOCK_METAHDR_LEN_V1;

    case MBLOCK_METAHDR_VERSION:
        return MBLOCK_METAHDR_LEN;

    default:
        abort();
    }
}

/**
 * struct mblock_filehdr_omf_v1 - mblock file meta header (version 1)
 */
struct mblock_filehdr_omf_v1 {
    uint32_t fh_uniq;
    uint8_t fh_fileid;
    uint8_t fh_rsvd1;
    uint16_t fh_rsvd2;
} HSE_PACKED;

/* Define set/get methods for mblock_filehdr_omf_v1 */
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_uniq, 32, v1);
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_fileid, 8, v1);
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_rsvd1, 8, v1);
OMF_GET_VER(struct mblock_filehdr_omf_v1, fh_rsvd2, 16, v1);

#define MBLOCK_FILEHDR_LEN_V1 (sizeof(struct mblock_filehdr_omf_v1))

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
    uint8_t fh_fileid;
    uint8_t fh_rsvd1;
    uint16_t fh_rsvd2;
    uint64_t fh_crc;
} HSE_PACKED;

/* Define set/get methods for mblock_filehdr_omf */
OMF_SETGET(struct mblock_filehdr_omf, fh_uniq, 32);
OMF_SETGET(struct mblock_filehdr_omf, fh_fileid, 8);
OMF_SETGET(struct mblock_filehdr_omf, fh_rsvd1, 8);
OMF_SETGET(struct mblock_filehdr_omf, fh_rsvd2, 16);
OMF_SETGET(struct mblock_filehdr_omf, fh_crc, 64);

#define MBLOCK_FILEHDR_LEN (sizeof(struct mblock_filehdr_omf))

static HSE_ALWAYS_INLINE uint32_t
omf_mblock_filehdr_len(uint32_t version)
{
    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        return MBLOCK_FILEHDR_LEN_V1;

    case MBLOCK_METAHDR_VERSION:
        return MBLOCK_FILEHDR_LEN;

    default:
        abort();
    }
}

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

#define MBLOCK_METAOID_LEN_V1 (sizeof(struct mblock_oid_omf_v1))

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
    uint32_t mblk_wlen;
    uint32_t mblk_rsvd1;
    uint64_t mblk_rsvd2;
    uint64_t mblk_crc;
} HSE_PACKED;

/* Define set/get methods for mblock_oid_omf */
OMF_SETGET(struct mblock_oid_omf, mblk_id, 64);
OMF_SETGET(struct mblock_oid_omf, mblk_wlen, 32);
OMF_SETGET(struct mblock_oid_omf, mblk_rsvd1, 32);
OMF_SETGET(struct mblock_oid_omf, mblk_rsvd2, 64);
OMF_SETGET(struct mblock_oid_omf, mblk_crc, 64);

#define MBLOCK_METAOID_LEN (sizeof(struct mblock_oid_omf))

static HSE_ALWAYS_INLINE uint32_t
omf_mblock_oid_len(uint32_t version)
{
    switch (version) {
    case MBLOCK_METAHDR_VERSION1:
        return MBLOCK_METAOID_LEN_V1;

    case MBLOCK_METAHDR_VERSION:
        return MBLOCK_METAOID_LEN;

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
 * omf_mblock_metahdr_gclose_set -
 *
 * @outbuf: set gclose field in meta header
 * @gclose: gclose value
 */
void
omf_mblock_metahdr_gclose_set(char *outbuf, bool gclose);

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
 * @gclose:  graceful close in the previous instance
 * @mh:      unpacked mblock file meta header (output)
 */
merr_t
omf_mblock_filehdr_unpack(
    const char *inbuf,
    uint32_t version,
    bool gclose,
    struct mblock_filehdr *fh);

/**
 * omf_mblock_oid_pack -
 *
 * @mbinfo: in-memory mblock oid info
 * @outbuf: packed mblock oid meta (output)
 */
void
omf_mblock_oid_pack(struct mblock_oid_info *mbinfo, char *outbuf);

/**
 * omf_mblock_oid_pack_zero -
 *
 * @outbuf: packed mblock oid meta (output)
 */
void
omf_mblock_oid_pack_zero(char *outbuf);

/**
 * omf_mblock_oid_unpack -
 *
 * @inbuf:   packed mblock oid meta
 * @version: mblock meta header on-media version
 * @gclose:  graceful close in the previous instance
 * @mbinfo:  unpacked mblock oid info (output)
 */
merr_t
omf_mblock_oid_unpack(
    const char *inbuf,
    uint32_t version,
    bool gclose,
    struct mblock_oid_info *mbinfo);

#endif /* MPOOL_OMF_H */
