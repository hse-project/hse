/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_TYPES_H
#define HSE_TYPES_H

#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stdint.h>

/** @defgroup ERRORS Errors
 * @{
 * Describes the HSE API return code type and associated utilities.
 */

/** @typedef hse_err_t
 * @brief Generic return type for the HSE library
 *
 * If this scalar quantity is 0 then the call succeeded. If it is non-zero, then
 * the 64-bit quantity can be used by the client in two ways: (1) call
 * hse_err_to_errno() to get a mapping to a POSIX errno value, and (2) call
 * hse_strerror() to get a textual reference about what error occurred and
 * where.
 *
 * The following special errno error codes are worth mentioning here.
 *
 * <table>
 *   <tr><th>errno</th><th>Caller action</th></tr>
 *   <tr><td>EAGAIN</td><td>The caller is expected to retry the operation.</td></tr>
 *   <tr><td>ECANCELED</td><td> The caller is expected to retry the operation in a
 *   new transaction. See @ref WRITE_CONFLICT "write conflicts".</td></tr>
 * </table>
 *
 * e.g., the code snippet below shows a typical non-transactional usage:
 *
 * @code{.c}
 * int retries = 0;
 * hse_err_t ret = 0;
 *
 * while (retries < MAX_RETRIES) {
 *    ret = hse_kvs_put(kvs_handle, flags, txn, key, k_len, val, v_len)
 *    if (EAGAIN != hse_err_to_errno(ret))
 *       break;
 *    retries++;
 * }
 * @endcode
 */
typedef uint64_t hse_err_t;

/** @brief Error context values */
enum hse_err_ctx {
    HSE_ERR_CTX_NONE, /**< No context. */
    HSE_ERR_CTX_TXN_EXPIRED, /**< Transaction timed out. */
};

/** @brief Smallest error context value. */
#define HSE_ERR_CTX_BASE HSE_ERR_CTX_NONE

/** @brief Largest error context value. */
#define HSE_ERR_CTX_MAX HSE_ERR_CTX_TXN_EXPIRED

/**@} ERRORS */

/** @addtogroup KVDB
 * @{
 */

/** @struct hse_kvdb
 * @brief Opaque structure, a pointer to which is a handle to an HSE key-value
 * database (KVDB).
 */
struct hse_kvdb;

/** @enum hse_mclass
 * @brief Media classes.
 */
enum hse_mclass {
    HSE_MCLASS_CAPACITY = 0, /**< Capacity media class. */
    HSE_MCLASS_STAGING = 1,  /**< Staging media class. */
    HSE_MCLASS_PMEM = 2,     /**< PMEM media class. */
};

#define HSE_MCLASS_BASE  HSE_MCLASS_CAPACITY  /**< Base media class. */
#define HSE_MCLASS_MAX   HSE_MCLASS_PMEM      /**< Maximum media class. */
#define HSE_MCLASS_COUNT (HSE_MCLASS_MAX + 1) /**< Number of media classes. */

#define HSE_MCLASS_CAPACITY_NAME "capacity" /**< Capacity media class name. */
#define HSE_MCLASS_STAGING_NAME  "staging"  /**< Staging media class name. */
#define HSE_MCLASS_PMEM_NAME     "pmem"     /**< PMEM media class name. */

/** @struct hse_mclass_info
 * @brief Media class information.
 */
struct hse_mclass_info {
    uint64_t mi_allocated_bytes; /**< Allocated storage space for the media class. */
    uint64_t mi_used_bytes;      /**< Used storage space for the media class. */
    uint64_t mi_reserved[8];     /**< Reserved space for future expansion. */
    char     mi_path[PATH_MAX];  /**< Path to a media class. */
};

/**@} KVDB */

/** @addtogroup KVS
 * @{
 */

/** @struct hse_kvs
 * @brief Opaque structure, a pointer to which is a handle to an HSE KVS
 * within a KVDB.
 */
struct hse_kvs;

/**@} KVS */

/** @addtogroup CURSORS
 * @{
 */

/** @struct hse_kvs_cursor
 * @brief Opaque structure, a pointer to which is a handle to a cursor within
 * a KVS.
 */
struct hse_kvs_cursor;

/**@} CURSORS */

/** @addtogroup TRANSACTIONS
 * @{
 */

/** @struct hse_kvdb_txn
 * @brief Opaque structure, a pointer to which is a handle to a transaction
 * within a KVDB.
 */
struct hse_kvdb_txn;

/** @brief Transaction state. */
enum hse_kvdb_txn_state {
    HSE_KVDB_TXN_INVALID = 0,   /**< Invalid state. */
    HSE_KVDB_TXN_ACTIVE = 1,    /**< Active state. */
    HSE_KVDB_TXN_COMMITTED = 2, /**< Committed state. */
    HSE_KVDB_TXN_ABORTED = 3,   /**< Aborted state. */
};

/** @} TRANSACTIONS */

#ifdef __cplusplus
}
#endif

#endif
