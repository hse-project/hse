/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_KVDB_OMF_H
#define HSE_KVDB_KVDB_OMF_H

#include <hse_util/omf.h>

#include <hse/hse_limits.h>

#define KVDB_OMF_REC_MAX PAGE_SIZE

enum {
    KVDB_LOG_MAGIC = 0xcafe2112,
    KVDB_LOG_VERSION5 = 5,
    KVDB_LOG_VERSION = KVDB_LOG_VERSION5,

    KVDB_LOG_TYPE_VERSION = 1,
    KVDB_LOG_TYPE_MDC = 2,
};

/* disposition
 * kvdb_log_finished()/kvdb_log_rollover() requires DONE dispositions be even.
 */
enum kvdb_log_disp {
    KVDB_LOG_DISP_CREATE = 1,
    KVDB_LOG_DISP_CREATE_DONE,
    KVDB_LOG_DISP_REPLACE,
    KVDB_LOG_DISP_REPLACE_DONE,
    KVDB_LOG_DISP_DESTROY,
    KVDB_LOG_DISP_DESTROY_DONE,
    KVDB_LOG_DISP_ABORT,
    KVDB_LOG_DISP_ABORT_DONE,
};

#define KVDB_LOG_DISP_MAKE_DONE(d)   ((d & 1) ? d + 1 : d)
#define KVDB_LOG_DISP_MAKE_UNDONE(d) ((d & 1) ? d : d - 1)

enum kvdb_log_mdc_id {
    KVDB_LOG_MDC_ID_CNDB = 0,
    KVDB_LOG_MDC_ID_C1,
    KVDB_LOG_MDC_ID_MAX = KVDB_LOG_MDC_ID_C1,
};

/* hdr must contain 4 bytes TYPE at offset 0 and 4 bytes LEN at offset 3.
 * if the hdr grows beyond 8 bytes, it will complicate backward compatibility
 */
struct kvdb_log_hdr2_omf {
    __le32 hdr_type;
    __le32 hdr_len;
} HSE_PACKED;

#define KVDB_LOG_OMF_LEN(x) (x - sizeof(struct kvdb_log_hdr2_omf))

/* the first 16 bytes must be hdr, magic, version in that order. */
struct kvdb_log_ver4_omf {
    struct kvdb_log_hdr2_omf hdr;
    __le32                   ver_magic;
    __le32                   ver_version;
    __le64                   ver_captgt;
} HSE_PACKED;

struct kvdb_log_mdc_omf {
    struct kvdb_log_hdr2_omf hdr;
    __le32                   mdc_disp;
    __le32                   mdc_id;
    __le64                   mdc_new_oid1;
    __le64                   mdc_new_oid2;
    __le64                   mdc_old_oid1;
    __le64                   mdc_old_oid2;
} HSE_PACKED;

OMF_SETGET(struct kvdb_log_hdr2_omf, hdr_type, 32);
OMF_SETGET(struct kvdb_log_hdr2_omf, hdr_len, 32);

OMF_SETGET(struct kvdb_log_ver4_omf, ver_magic, 32);
OMF_SETGET(struct kvdb_log_ver4_omf, ver_version, 32);
OMF_SETGET(struct kvdb_log_ver4_omf, ver_captgt, 64);

OMF_SETGET(struct kvdb_log_mdc_omf, mdc_disp, 32);
OMF_SETGET(struct kvdb_log_mdc_omf, mdc_id, 32);
OMF_SETGET(struct kvdb_log_mdc_omf, mdc_new_oid1, 64);
OMF_SETGET(struct kvdb_log_mdc_omf, mdc_new_oid2, 64);
OMF_SETGET(struct kvdb_log_mdc_omf, mdc_old_oid1, 64);
OMF_SETGET(struct kvdb_log_mdc_omf, mdc_old_oid2, 64);

/** struct kvdb_kvmeta_omf() -
 * @kvmt_klen:
 * @kvmt_vlen:
 */
struct kvdb_kvmeta_omf {
    __le64 kvmt_klen;
    __le64 kvmt_vlen;
} HSE_PACKED;

OMF_SETGET(struct kvdb_kvmeta_omf, kvmt_klen, 64);
OMF_SETGET(struct kvdb_kvmeta_omf, kvmt_vlen, 64);
#endif /* HSE_KVDB_KVDB_OMF_H */
