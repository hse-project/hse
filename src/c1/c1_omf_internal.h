/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_OMF_INTERNAL_H
#define HSE_C1_OMF_INTERNAL_H

#include "c1_private.h"

union c1_record {
    struct c1_version      n;
    struct c1_info         f;
    struct c1_desc         d;
    struct c1_ingest       i;
    struct c1_log          l;
    struct c1_kvb          b;
    struct c1_kvtuple_meta k;
    struct c1_complete     c;
    struct c1_reset        r;
    struct c1_treetxn      t;
    struct c1_vtuple_meta  v;
    struct c1_mblk_meta    m;
};

/*
 * c1_unpack_hdlr(): Unpack handler for c1 omf structs
 *
 * @omf: on-media structure
 * @rec: unpacked record (output)
 * @omf_len: size of on-media structure (output)
 */
typedef merr_t(c1_unpack_hdlr)(char *omf, union c1_record *rec, u32 *omf_len);

/*
 * c1_unpack_hinfo: Version table for a c1 record type. This table contains
 *                  handlers to unpack different versions of omf struct for
 *                  this type.
 *
 * c1_uhdr: unpack handler for the version 'c1_uver'
 * c1_uver: version number
 */
struct c1_unpack_hinfo {
    c1_unpack_hdlr *c1_uhdr;
    u32             c1_uver;
};

/*
 * c1_unpack_type: Mapping from a c1 record type to its version table.
 *
 * c1_uhinfo: pointer to version table
 * c1_uverc: number of entries in the version table for this record type
 */
struct c1_unpack_type {
    struct c1_unpack_hinfo *c1_uhinfo;
    u16                     c1_uverc;
};

/*
 * c1_record_unpack(): Generic function to unpack any c1 record type.
 *                     This record must contain c1 header as the first field,
 *                     as the header contains record type.
 *
 * @omf: on-media structure
 * @ver: on-media structure version
 * @rec: in-memory struct to unpack into (output)
 */
merr_t
c1_record_unpack(char *omf, u32 ver, union c1_record *rec);

/*
 * c1_record_unpack_bytype(): Generic function to unpack the specified
 *                            c1 record type.
 *
 * @omf: on-media structure
 * @type: c1 record type
 * @ver: on-media structure version
 * @rec: in-memory struct to unpack into (output)
 */
merr_t
c1_record_unpack_bytype(char *omf, u32 type, u32 ver, union c1_record *rec);

/*
 * c1_record_type2len(): Returns omf size for the specified version and
 *                       record type.
 *
 * @type: c1 record type
 * @ver: on-media structure version
 * @omf_len: size of on-media structure for the specified version (output)
 */
merr_t
c1_record_type2len(u32 type, u32 ver, u32 *omf_len);

/*
 * c1_record_omf2len(): Returns omf size for the specified version and omf
 *                      struct. This record must contain c1 header as the
 *                      first field, as the header contains record type.
 *
 * @omf: on-media structure
 * @ver: on-media structure version
 * @omf_len: size of on-media structure for the specified version (output)
 */
merr_t
c1_record_omf2len(char *omf, u32 ver, u32 *omf_len);

/*
 * c1_record_unpack_hdlr_get(): Returns handler for the specified version
 *                              by binary searching the version table.
 *
 * @omf: on-media structure
 * @ver: on-media structure version
 * @omf_len: size of on-media structure for the specified version (output)
 */
c1_unpack_hdlr *
c1_record_unpack_hdlr_get(struct c1_unpack_type *upt, u32 ver);

/* Unpack routine for c1 header */

merr_t
omf_c1_header_unpack(char *omf, struct c1_header *hdr);

u32
omf_c1_header_unpack_len(void);

u32
omf_c1_header_type(char *omf);

/*
 * Type specific unpack routines goes below.
 */

/* C1_TYPE_VERSION */
merr_t
omf_c1_ver_unpack(char *omf, struct c1_version *vers);

/* C1_TYPE_INFO */
merr_t
omf_c1_info_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_DESC */
merr_t
omf_c1_desc_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_INGEST */
merr_t
omf_c1_ingest_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_KVLOG */
merr_t
omf_c1_kvlog_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_KVB */
merr_t
omf_c1_kvb_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_KVT */
merr_t
omf_c1_kvtuple_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_COMPLETE */
merr_t
omf_c1_complete_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_RESET */
merr_t
omf_c1_reset_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_TXN */
merr_t
omf_c1_treetxn_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_VT */
merr_t
omf_c1_vtuple_unpack(char *omf, union c1_record *rec, u32 *omf_len);

/* C1_TYPE_MBLK */
merr_t
omf_c1_mblk_unpack(char *omf, union c1_record *rec, u32 *omf_len);

#endif /* HSE_C1_OMF_INTERNAL_H */
