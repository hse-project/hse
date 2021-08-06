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

/** @addtogroup TYPES
 * @{
 */ 
#define HSE_FLAG_NONE (0u) /**< Represents no flags */

#define HSE_FLAG_SYNC_ASYNC (1u << 0) /**< make the sync operation asynchronous */
#define HSE_FLAG_SYNC_REFWAIT (1u << 1) /**< block sync while there are refs on the kvms being ingested */

#define HSE_FLAG_PUT_PRIORITY  (1u << 0) /**< Operation will not be throttled */
#define HSE_FLAG_PUT_VCOMP_OFF (1u << 1) /**< Value will not be compressed */

/** @brief Turns of value compression on puts. */
#define HSE_FLAG_PUT_VALUE_COMPRESSION_OFF HSE_FLAG_PUT_VCOMP_OFF 

/* Flags for cursor usage */
#define HSE_FLAG_CURSOR_REVERSE     (1u << 0) /**< Move the cursor in reverse */

/** @} TYPES */

#ifdef HSE_EXPERIMENTAL
/**
 * Flags for KVDB compaction
 */
#define HSE_FLAG_KVDB_COMPACT_CANCEL   (1u << 0)
#define HSE_FLAG_KVDB_COMPACT_SAMP_LWM (1u << 1)
#endif

#ifdef __cplusplus
}
#endif

#endif
