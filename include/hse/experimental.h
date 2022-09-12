/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/* The interfaces defined in this file are provided only for use by
 * internal components of the HSE library.  They are not part of the
 * HSE library public API and hence are subject to change (e.g.,
 * presence, stability, name, arguments, semantics) without notice.
 */

#ifndef HSE_EXPERIMENTAL_H
#define HSE_EXPERIMENTAL_H

#include <hse/types.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

/* hse_kvdb_compact() flags */
#define HSE_KVDB_COMPACT_CANCEL   (1u << 0)
#define HSE_KVDB_COMPACT_SAMP_LWM (1u << 1)

/** @addtogroup KVDB Key-Value Database (KVDB)
 * @{
 */

/** @brief Status of a compaction request. */
struct hse_kvdb_compact_status {
    unsigned int kvcs_samp_lwm;  /**< space amp low water mark (%). */
    unsigned int kvcs_samp_hwm;  /**< space amp high water mark (%). */
    unsigned int kvcs_samp_curr; /**< current space amp (%). */
    unsigned int kvcs_active;    /**< is an externally requested compaction underway. */
    unsigned int kvcs_canceled;  /**< was an externally requested compaction canceled. */
};

/** @brief Request a data compaction operation.
 *
 * In managing the data within an HSE KVDB, there are maintenance activities
 * that occur as background processing. The application may be aware that it is
 * advantageous to do enough maintenance now for the database to be as compact
 * as it ever would be in normal operation.
 *
 * See the function hse_kvdb_compact_status_get().
 *
 * <b>Flags:</b>
 * @arg HSE_KVDB_COMPACT_CANCEL - Cancel an ongoing compaction request.
 * @arg HSE_KVDB_COMPACT_SAMP_LWM - Compact to the space amp low watermark.
 *
 * @note This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param flags: Compaction flags.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p flags must not be 0.
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_compact(struct hse_kvdb *kvdb, unsigned int flags);

/** @brief Get status of an ongoing compaction activity.
 *
 * The caller can examine the fields of the hse_kvdb_compact_status struct to
 * determine the current state of maintenance compaction.
 *
 * @note This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param[out] status: Status of compaction request.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p status must not be NULL.
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_compact_status_get(struct hse_kvdb *kvdb, struct hse_kvdb_compact_status *status);

/**@} KVDB */

/** @addtogroup KVS Key-Value Store (KVS)
 * @{
 */

/**@} KVS */

#pragma GCC visibility pop

#ifdef __cplusplus
}
#endif

#endif
