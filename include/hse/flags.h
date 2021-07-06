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

#define HSE_FLAG_NONE 0 /* Represents no flags */

/**
 * Flags for sync operation
 */

#define HSE_FLAG_SYNC_ASYNC (1 << 0)/* make the sync operation asynchronous */

/**
 * Flags for PUT operation
 */

#define HSE_FLAG_PUT_PRIORITY              (1 << 0) /* Operation will not be throttled */
#define HSE_FLAG_PUT_VALUE_COMPRESSION_ON  (1 << 1) /* Value will be compressed */
#define HSE_FLAG_PUT_VALUE_COMPRESSION_OFF (1 << 2) /* Value will not be compressed */

/**
 * Flags for cursor usage
 */

#define HSE_FLAG_CURSOR_REVERSE     (1 << 0) /* Move the cursor in reverse */
#define HSE_FLAG_CURSOR_BIND_TXN    (1 << 1) /* Bind the cursor to a transaction */
#define HSE_FLAG_CURSOR_STATIC_VIEW (1 << 2) /* Bound cursor's view is static */

#ifdef HSE_EXPERIMENTAL
/**
 * Flags for KVDB compaction
 */
#define HSE_FLAG_KVDB_COMPACT_CANCEL   (1 << 0)
#define HSE_FLAG_KVDB_COMPACT_SAMP_LWM (1 << 1)
#endif

#ifdef __cplusplus
}
#endif

#endif
