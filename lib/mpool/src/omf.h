/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_OMF_H
#define MPOOL_OMF_H

#include <hse_util/omf.h>
#include <hse_util/hse_err.h>

struct mdc_loghdr;
struct mdc_rechdr;
struct mblock_metahdr;
struct mblock_filehdr;

/*
 * MDC OMF
 */

/**
 * struct mdc_loghdr_omf - OMF for MDC log header
 *
 * @lh_vers:  version
 * @lh_magic: magic
 * @lh_rsvd:  reserved
 * @lh_gen:   generation
 * @lh_crc:   loghdr CRC
 */
struct mdc_loghdr_omf {
    __le32 lh_vers;
    __le32 lh_magic;
    __le32 lh_rsvd;
    __le64 lh_gen;
    __le32 lh_crc;
} HSE_PACKED;

/* Define set/get methods for mdc_loghdr_omf */
OMF_SETGET(struct mdc_loghdr_omf, lh_vers, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_magic, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_rsvd, 32);
OMF_SETGET(struct mdc_loghdr_omf, lh_gen, 64);
OMF_SETGET(struct mdc_loghdr_omf, lh_crc, 32);

/**
 * struct mdc_rechdr_omf - OMF for MDC record header
 *
 * @rh_crc:  record CRC
 * @rh_size: record length
 */
struct mdc_rechdr_omf {
    __le32 rh_crc;
    __le64 rh_size;
} HSE_PACKED;

/* Define set/get methods for mdc_rechdr_omf */
OMF_SETGET(struct mdc_rechdr_omf, rh_crc, 32);
OMF_SETGET(struct mdc_rechdr_omf, rh_size, 64);

/**
 * omf_mdc_loghdr_pack_htole - Pack lh into outbuf
 *
 * @lh:     in-memory log header
 * @outbuf: packed log header (output)
 */
merr_t
omf_mdc_loghdr_pack_htole(struct mdc_loghdr *lh, char *outbuf);

/**
 * omf_mdc_loghdr_unpack_letoh - Unpack inbuf into lh
 *
 * @inbuf: packed log header
 * @lh:    unpacked in-memory log header (output)
 */
merr_t
omf_mdc_loghdr_unpack_letoh(const char *inbuf, struct mdc_loghdr *lh);

/**
 * omf_mdc_loghdr_len - return log header length
 */
size_t
omf_mdc_loghdr_len(void);

/**
 * omf_mdc_rechdr_unpack_letoh - Unpack inbuf into rh
 *
 * @inbuf: packed log header
 * @rh:    unpacked in-memory record header (output)
 */
void
omf_mdc_rechdr_unpack_letoh(const char *inbuf, struct mdc_rechdr *rh);

/**
 * omf_mdc_rechdr_len - return record header length
 */
size_t
omf_mdc_rechdr_len(void);

/*
 * Mblock Meta OMF
 */

/**
 * struct mblock_metahdr_omf - mblock fset meta header
 *
 * @mh_vers:      version
 * @mh_magic:     magic
 * @mh_fszmax_gb: max file size
 * @mh_mblksz_mb: mblock size
 * @mh_mcid:      media class ID
 * @mh_fcnt:      file count
 * @mh_blkbits:   no. of bits used for block offset
 * @mh_mcbits:    no. of media class bits
 */
struct mblock_metahdr_omf {
    __le32 mh_vers;
    __le32 mh_magic;
    __le32 mh_fszmax_gb;
    __le16 mh_mblksz_mb;
    u8     mh_mcid;
    u8     mh_fcnt;
    u8     mh_blkbits;
    u8     mh_mcbits;
} HSE_PACKED;

/* Define set/get methods for mblock_metahdr_omf */
OMF_SETGET(struct mblock_metahdr_omf, mh_vers, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_magic, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_fszmax_gb, 32);
OMF_SETGET(struct mblock_metahdr_omf, mh_mblksz_mb, 16);
OMF_SETGET(struct mblock_metahdr_omf, mh_mcid, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_fcnt, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_blkbits, 8);
OMF_SETGET(struct mblock_metahdr_omf, mh_mcbits, 8);

/**
 * struct mblock_filehdr_omf - mblock file meta header
 *
 * @fh_uniq:   uniquifier
 * @fh_fileid: file id
 * @fh_rsvd1:  reserved 1
 * @fh_rsvd2:  reserved 2
 */
struct mblock_filehdr_omf {
    __le32 fh_uniq;
    u8     fh_fileid;
    u8     fh_rsvd1;
    __le16 fh_rsvd2;
} HSE_PACKED;

/* Define set/get methods for mblock_filehdr_omf */
OMF_SETGET(struct mblock_filehdr_omf, fh_uniq, 32);
OMF_SETGET(struct mblock_filehdr_omf, fh_fileid, 8);
OMF_SETGET(struct mblock_filehdr_omf, fh_rsvd1, 8);
OMF_SETGET(struct mblock_filehdr_omf, fh_rsvd2, 16);

/**
 * struct mblock_oid_omf - per mblock OMF
 *
 * @mblk_id:   mblock ID
 * @mblk_wlen: mblock write length
 */
struct mblock_oid_omf {
    __le64 mblk_id;
    __le32 mblk_wlen;
} HSE_PACKED;

/* Define set/get methods for mblock_oid_omf */
OMF_SETGET(struct mblock_oid_omf, mblk_id, 64);
OMF_SETGET(struct mblock_oid_omf, mblk_wlen, 32);

#define MBLOCK_FILE_META_OIDLEN (sizeof(struct mblock_oid_omf))

/**
 * omf_mblock_metahdr_pack_htole -
 *
 * @mh:     in-memory mblock meta header
 * @outbuf: packed mblock meta header (output)
 */
void
omf_mblock_metahdr_pack_htole(struct mblock_metahdr *mh, char *outbuf);

/**
 * omf_mblock_metahdr_unpack_letoh -
 *
 * @inbuf: packed mblock meta header
 * @mh:    unpacked mblock meta header (output)
 */
void
omf_mblock_metahdr_unpack_letoh(const char *inbuf, struct mblock_metahdr *mh);

/**
 * omf_mblock_filehdr_pack_htole -
 *
 * @fh:     in-memory mblock file meta header
 * @outbuf: packed mblock file meta header (output)
 */
void
omf_mblock_filehdr_pack_htole(struct mblock_filehdr *fh, char *outbuf);

/**
 * omf_mblock_filehdr_unpack_letoh -
 *
 * @inbuf: packed mblock file meta header
 * @mh:    unpacked mblock file meta header (output)
 */
void
omf_mblock_filehdr_unpack_letoh(const char *inbuf, struct mblock_filehdr *fh);

#endif /* MPOOL_OMF_H */
