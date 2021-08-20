/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

/** @file hse.h
 */

#ifndef HSE_FLAGS_H
#define HSE_FLAGS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Documentation for these flags appears in hse.h */

/* Do not use the following, marked for removal pre-2.0 final release */
#define HSE_FLAG_NONE (0u)

/* hse_kvdb_sync() flags */
#define HSE_KVDB_SYNC_ASYNC (1u << 0)
#define HSE_KVDB_SYNC_RSVD1 (1u << 1)

/* Do not use the following, marked for removal pre-2.0 final release */
#define HSE_FLAG_SYNC_ASYNC   HSE_KVDB_SYNC_ASYNC

/* hse_kvs_put() flags */
#define HSE_KVS_PUT_PRIO      (1u << 0)
#define HSE_KVS_PUT_VCOMP_OFF (1u << 1)

/* Do not use the following, marked for removal pre-2.0 final release */
#define HSE_FLAG_PUT_PRIORITY              HSE_KVS_PUT_PRIO
#define HSE_FLAG_PUT_VCOMP_OFF             HSE_KVS_PUT_VCOMP_OFF
#define HSE_FLAG_PUT_VALUE_COMPRESSION_OFF HSE_FLAG_PUT_VCOMP_OFF

/* hse_kvs_cursor_create() flags */
#define HSE_CURSOR_CREATE_REV (1u << 0)

/* Do not use the following, marked for removal pre-2.0 final release */
#define HSE_FLAG_CURSOR_REVERSE HSE_CURSOR_CREATE_REV

#ifdef HSE_EXPERIMENTAL
/* hse_kvdb_compact() flags */
#define HSE_KVDB_COMPACT_CANCEL   (1u << 0)
#define HSE_KVDB_COMPACT_SAMP_LWM (1u << 1)

/* Do not use the following, marked for removal pre-2.0 final release */
#define HSE_FLAG_KVDB_COMPACT_CANCEL   HSE_KVDB_COMPACT_CANCEL
#define HSE_FLAG_KVDB_COMPACT_SAMP_LWM HSE_KVDB_COMPACT_SAMP_LWM
#endif

#ifdef __cplusplus
}
#endif

#endif
