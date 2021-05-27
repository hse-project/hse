/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_LIMITS_H
#define HSE_LIMITS_H

#ifdef __cplusplus
extern "C" {
#endif

/** @addtogroup LIMITS Limits
 * @{
 */


/** @brief  Maximum number of KVS's contained within one KVDB.
 */
#define HSE_KVS_COUNT_MAX (256)

/** @brief Maximum key length.
 *
 * A common requirement for key length for the software above HSE KVDB is 1024.
 * Combined with a discriminant and (potentially) a chunk key, this pushes us to
 * 1030 bytes keys. Looking at the packing for the on-media format for data, we
 * can have at most 3 keys of such large size in a 4k page. Lopping off 64-bytes
 * for other data, and we can have 3 keys of 1344 bytes.
 */
#define HSE_KVS_KEY_LEN_MAX 1344

/** @brief Max value length is 1MiB */
#define HSE_KVS_VALUE_LEN_MAX (1024 * 1024)

/** @brief Max key prefix length */
#define HSE_KVS_PFX_LEN_MAX 32

/** @brief Max KVS name lengths */
#define HSE_KVS_NAME_LEN_MAX 32

/** @} LIMITS */

#ifdef __cplusplus
}
#endif

#endif
