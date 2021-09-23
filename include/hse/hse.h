/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_HSE_H
#define HSE_HSE_H

/* MTF_MOCK_DECL(hse) */

/** @mainpage Overview
 *
 * This documentation is geared towards describing the structure of the HSE API
 * and the specifics of each entry point's operation. Refer to
 * https://hse-project.github.io for a conceptual overview of HSE.
 *
 * <h3>Terminology</h3>
 *
 * @arg <b>KVS</b> - Key-value store, containing zero or more key-value pairs
 *
 * @arg <b>KVDB</b> - Key-value database, comprised of one or more KVSs and
 * defining a transaction domain
 *
 * @arg <b>key</b> - A byte string used to uniquely identify values for storage,
 * retrieval, and deletion in a KVS
 *
 * @arg <b>segmented key</b> - A key that is logically divided into N segments
 * (N >= 2), arranged to group related key-value pairs when keys are sorted
 * lexicographically
 *
 * @arg <b>key prefix</b> - For segmented keys, the first K segments
 * (1 <= K < N)
 *
 * @arg <b>key prefix length</b> - The length of a key prefix (bytes)
 */

/** @page examples Examples
 * See the samples directory in the source tree for examples. Here is a simple
 * one.
 * @include ex2_simple_ops.c
 */

#include <hse/flags.h>
#include <hse/limits.h>
#include <hse/types.h>
#include <hse/version.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

#pragma GCC visibility push(default)

/** @addtogroup ERRORS
 * @{
 * Describes the HSE API return code type and associated utilities.
 */

/** @brief Return an hse_err_t value's errno representation.
 *
 * The hse_err_t scalar value @p err is translated into its errno equivalent.
 *
 * @note This function is thread safe.
 *
 * @param err: Error value returned from an HSE API function.
 *
 * @returns Error's errno equivalent.
 */
int
hse_err_to_errno(hse_err_t err);

/** @brief Return an hse_err_t value's string representation.
 *
 * The hse_err_t scalar value @p err is decoded into a NULL-terminated string
 * representation giving more information about the error and where it occurred.
 * The string will be truncated if @p buf_len is too small (a @p buf_len value
 * of 128 is sufficient to avoid truncation of most error strings).
 *
 * @note This function is thread safe.
 *
 * @param err: Error value returned from an HSE API function.
 * @param[in,out] buf: Buffer to hold the formatted string.
 * @param buf_len: Length of buffer.
 *
 * @returns The number of characters (excluding the terminating NULL byte) which
 * would have been written to the final string if enough space had been
 * available.
 */
size_t
hse_strerror(hse_err_t err, char *buf, size_t buf_len);

/** @brief Return an hse_err_t value's error context.
 *
 * The error context value is retrieved from the hse_err_t value.
 *
 * @note This function is thread safe.
 *
 * @param err: Error value returned from an HSE API function.
 *
 * @returns The error's context.
 */
enum hse_err_ctx
hse_err_to_ctx(hse_err_t err);

/**@} ERRORS */

/** @defgroup SUBSYS Subsystem
 * @{
 */

/** @brief Initialize the HSE subsystem.
 *
 * This function initializes a range of different internal HSE structures. It
 * must be called before any other HSE functions are used.
 *
 * @note This function is not thread safe and is idempotent.
 *
 * @param config: Path to a global configuration file.
 * @param paramc: Number of initialization parameters in @p paramv.
 * @param paramv: List of parameters in key=value format.
 *
 * @returns Error status.
 */
hse_err_t
hse_init(const char *config, size_t paramc, const char *const *paramv);

/** @brief Shutdown the HSE subsystem.
 *
 * This function cleanly finalizes a range of different internal HSE structures.
 * It should be called prior to application exit.
 *
 * @warning After invoking this function, calling any other HSE functions will
 * result in undefined behavior unless HSE is re-initialized.
 *
 * @note This function is not thread safe.
 */
void
hse_fini(void);

/** @} SUBSYS */

/** @defgroup KVDB Key-Value Database (KVDB)
 * @{
 */

/** @brief Close a KVDB.
 *
 * @warning After invoking this function, calling any other KVDB functions will
 * result in undefined behavior unless the KVDB is re-opened.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 *
 * @remark @p kvdb must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_close(struct hse_kvdb *kvdb);

/** @brief Create a KVDB.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory.
 * @param paramc: Number of configuration parameters in @p paramv.
 * @param paramv: List of parameters in key=value format.
 *
 * @remark @p kvdb_home must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_create(const char *kvdb_home, size_t paramc, const char *const *paramv);

/** @brief Drop a KVDB.
 *
 * @warning It is an error to call this function on a KVDB that is open.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory.
 *
 * @remark @p kvdb_home must not be NULL.
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_drop(const char *kvdb_home);

/** @brief Get the KVDB home.
 *
 * @note This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 *
 * @remark @p kvdb must not be NULL.
 *
 * @returns KVDB home.
 * @retval NULL if given an invalid KVDB handle.
 */
const char *
hse_kvdb_home_get(struct hse_kvdb *kvdb);

/** @brief Get the names of the KVSs within the given KVDB.
 *
 * Key-value stores (KVSs) are opened by name. This function allocates a vector
 * of allocated strings, each containing the NULL-terminated name of a KVS. The
 * memory must be freed via hse_kvdb_kvs_names_free().
 *
 * @note This function is thread safe.
 *
 * Example Usage:
 *
 * @code{.c}
 *     int namec;
 *     char **namev;
 *     hse_err_t err;
 *
 *     err = hse_kvdb_kvs_names_get(kvdb, &namec, &namev);
 *     if (!err) {
 *         for (int i = 0; i < namec; i++)
 *             printf("%s\n", namev[i]);
 *     }
 *     hse_kvdb_kvs_names_free(namev);
 * @endcode
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param[out] namec: Number of KVSs in the KVDB.
 * @param[out] namev: Vector of KVSs allocated by the function.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p namev must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_kvs_names_get(struct hse_kvdb *kvdb, size_t *namec, char ***namev);

/** @brief Free the names collection obtained through hse_kvdb_kvs_names_get().
 *
 * @note This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param namev: Vector of KVS names that hse_kvdb_kvs_names_get() output.
 */
void
hse_kvdb_kvs_names_free(struct hse_kvdb *kvdb, char **namev);

/** @brief Open a KVDB.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory.
 * @param paramc: Number of configuration parameters in @p paramv.
 * @param paramv: List of parameters in key=value format.
 * @param[out] kvdb: Handle to access the opened KVDB.
 *
 * @remark The KVDB must have already been created.
 * @remark @p kvdb_home must not be NULL.
 * @remark @p kvdb must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_open(
    const char *       kvdb_home,
    size_t             paramc,
    const char *const *paramv,
    struct hse_kvdb ** kvdb);

/** @brief Add new media class storage to an existing offline KVDB.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory.
 * @param paramc: Number of configuration parameters in @p paramv.
 * @param paramv: List of KVDB create-time parameters in key=value format.
 *
 * @remark @p kvdb_home must not be NULL.
 * @remark @p KVBD must have already been created.
 * @remark @p paramv must not be NULL.
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_storage_add(const char *kvdb_home, size_t paramc, const char *const *paramv);

/** @brief Sync data in all of the referenced KVDB's KVSs to stable media.
 *
 * @note This function is thread safe.
 *
 * <b>Flags:</b>
 * @arg HSE_KVDB_SYNC_ASYNC - Return immediately after initiating operation
 * instead of waiting for completion.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param flags: Flags for operation specialization.
 *
 * @remark @p kvdb must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_sync(struct hse_kvdb *kvdb, unsigned int flags);

/**@} KVDB */

/** @defgroup KVS Key-Value Store (KVS)
 * @{
 */

/** @brief Close an open KVS.
 *
 * @warning After invoking this function, calling any other KVS functions will
 * result in undefined behavior unless the KVS is re-opened.
 *
 * @note This function is not thread safe.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open().
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *kvs);

/** @brief Create a KVS within the referenced KVDB.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param kvs_name: KVS name.
 * @param paramc: Number of configuration parameters in @p paramv.
 * @param paramv: List of parameters in key=value format.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p kvs_name must be non-NULL.
 * @remark @p kvs_name must be NULL-terminated.
 * @remark strlen(@p kvs_name) must be less than HSE_KVS_NAME_LEN_MAX.
 * @remark @p kvs_name must match the following pattern: [-_A-Za-z0-9]+.
 * @remark @p kvs_name cannot already exist.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_kvs_create(
    struct hse_kvdb *  kvdb,
    const char *       kvs_name,
    size_t             paramc,
    const char *const *paramv);

/** @brief Drop a KVS from the referenced KVDB.
 *
 * @warning It is an error to call this function on a KVS that is open.
 *
 * @note This function is not thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param kvs_name: KVS name.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p kvs_name must not be NULL.
 * @remark @p kvs_name must be NULL-terminated.
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *kvdb, const char *kvs_name);

/** @brief Open a KVS in a KVDB.
 *
 * This function is not thread safe.
 *
 * @param handle: KVDB handle from hse_kvdb_open().
 * @param kvs_name: KVS name.
 * @param paramc: Number of configuration parameters in @p paramv.
 * @param paramv: List of parameters in key=value format.
 * @param[out] kvs_out: Handle to access the opened KVS.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p kvs_name must not be NULL.
 * @remark @p kvs_name must be NULL-terminated.
 * @remark @p kvs_out must not be NULL.
 *
 * @returns Error status.
 */
hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *  handle,
    const char *       kvs_name,
    const size_t       paramc,
    const char *const *paramv,
    struct hse_kvs **  kvs_out);

/** @brief Delete the key and its associated value from the KVS.
 *
 * It is not an error if the key does not exist within the KVS. See @ref
 * TRANSACTIONS for information on how deletes within transactions are handled.
 *
 * @note This function is thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open().
 * @param flags: Flags for operation specialization.
 * @param txn: Transaction context (optional).
 * @param key: Key to be deleted from @p kvs.
 * @param key_len: Length of @p key.
 *
 * @remark @p kvs must not be NULL.
 * @remark @p key must not be NULL.
 * @remark @p key_len must be within the range of [1, HSE_KVS_KEY_LEN_MAX].
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         key,
    size_t               key_len);

/** @brief Retrieve the value for a given key from the KVS.
 *
 * If the key exists in the KVS, then the referent of @p found is set to true.
 * If the caller's value buffer is large enough then the data will be returned.
 * Regardless, the actual length of the value is placed in @p val_len. See @ref
 * TRANSACTIONS for information on how gets within transactions are handled.
 *
 * @note This function is thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open().
 * @param flags: Flags for operation specialization.
 * @param txn: Transaction context (optional).
 * @param key: Key to get from @p kvs.
 * @param key_len: Length of @p key.
 * @param[out] found: Whether or not @p key was found.
 * @param[in,out] buf: Buffer into which the value associated with @p key will
 * be copied (optional).
 * @param buf_len: Length of @p buf.
 * @param[out] val_len: Actual length of value if @p key was found.
 *
 * @remark @p kvs must not be NULL.
 * @remark @p key must not be NULL.
 * @remark @p key_len must be within the range of [1, HSE_KVS_KEY_LEN_MAX].
 * @remark @p found must not be NULL.
 * @remark @p val_len must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_get(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         key,
    size_t               key_len,
    bool *               found,
    void *               buf,
    size_t               buf_len,
    size_t *             val_len);

/** @brief Get the name of a KVS.
 *
 * @note This function is thread safe.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 *
 * @remark @p kvs must not be NULL.
 *
 * @returns KVS name.
 * @retval NULL if given an invalid KVS handle.
 */
const char *
hse_kvs_name_get(struct hse_kvs *kvs);

/** @brief Delete all key-value pairs matching the key prefix from a KVS storing
 * segmented keys.
 *
 * This interface is used to delete an entire range of segmented keys. To do
 * this the caller passes a filter with a length equal to the KVSs key prefix
 * length. It is not an error if no keys exist matching the filter. If there is
 * a filtered iteration in progress, then that iteration can fail if
 * hse_kvs_prefix_delete() is called with a filter matching the iteration.
 *
 * If hse_kvs_prefix_delete() is called from a transaction context, it affects
 * no key-value mutations that are part of the same transaction. Stated
 * differently, for KVS commands issued within a transaction, all calls to
 * hse_kvs_prefix_delete() are treated as though they were issued serially at
 * the beginning of the transaction regardless of the actual order these
 * commands appeared in.
 *
 * @note This function is thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open().
 * @param flags: Flags for operation specialization.
 * @param txn: Transaction context (optional).
 * @param pfx: Prefix of keys to delete.
 * @param pfx_len: Length of @p pfx.
 *
 * @remark @p kvs must not be NULL.
 * @remark @p pfx_len must be less than or equal to HSE_KVS_PFX_LEN_MAX.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         pfx,
    size_t               pfx_len);

/** @brief Put a key-value pair into KVS.
 *
 * If the key already exists in the KVS then the value is effectively
 * overwritten. See @ref TRANSACTIONS for information on how puts within
 * transactions are handled.
 *
 * The HSE KVDB attempts to maintain reasonable QoS and for high-throughput
 * clients this results in very short sleep's being inserted into the put path.
 * For some kinds of data (e.g., control metadata) the client may wish to not
 * experience that delay. For relatively low data rate uses, the caller can set
 * the HSE_KVS_PUT_PRIO flag for an hse_kvs_put(). Care should be taken when
 * doing so to ensure that the system does not become overrun. As a rough
 * approximation, doing 1M priority puts per second marked as PRIO is likely an
 * issue. On the other hand, doing 1K small puts per second marked as PRIO is
 * almost certainly fine.
 *
 * If compression is enabled for the given kvs, then hse_kvs_put() will attempt
 * to compress the value unless the HSE_KVS_PUT_VCOMP_OFF flag is given.
 * Otherwise, the HSE_KVS_PUT_VCOMP_OFF flag is ignored.
 *
 * @note This function is thread safe.
 *
 * <b>Flags:</b>
 * @arg HSE_KVS_PUT_PRIO - Operation will not be throttled.
 * @arg HSE_KVS_PUT_VCOMP_OFF - Value will not be compressed.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open().
 * @param flags: Flags for operation specialization.
 * @param txn: Transaction context (optional).
 * @param key: Key to put into @p kvs.
 * @param key_len: Length of @p key.
 * @param val: Value associated with @p key (optional).
 * @param val_len: Length of @p value.
 *
 * @remark @p kvs must not be NULL.
 * @remark @p key must not be NULL.
 * @remark @p key_len must be within the range of [1, HSE_KVS_KEY_LEN_MAX].
 * @remark @p val_len must be within the range of [0, HSE_KVS_VALUE_LEN_MAX].
 *
 * @returns Error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_put(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         key,
    size_t               key_len,
    const void *         val,
    size_t               val_len);

/**@} KVS */

/** @defgroup TRANSACTIONS Transactions
 * The HSE KVDB provides transactions with operations spanning KVSs within a
 * single KVDB. These transactions have snapshot isolation (a specific form of
 * MVCC) with the normal semantics (see "Concurrency Control and Recovery in
 * Database Systems" by PA Bernstein).
 *
 * One unusual aspect of the API as it relates to transactions is that the data
 * object that is used to hold client-level transaction state is allocated
 * separately from the transaction being initiated. As a result, the same object
 * handle should be reused again and again.
 *
 * In addition, there is very limited coupling between threading and
 * transactions. A single thread may have many transactions in flight
 * simultaneously. Also operations within a transaction can be performed by
 * multiple threads. The latter mode of operation must currently restrict calls
 * so that only one thread is actively performing an operation in the context of
 * a particular transaction at any particular time.
 *
 * The general lifecycle of a transaction is as follows:
 *
 *                       +----------+
 *                       | INVALID  |
 *                       +----------+
 *                             |
 *                             v
 *                       +----------+
 *     +---------------->|  ACTIVE  |<----------------+
 *     |                 +----------+                 |
 *     |  +-----------+    |      |     +----------+  |
 *     +--| COMMITTED |<---+      +---->| ABORTED  |--+
 *        +-----------+                 +----------+
 *
 * When a transaction is initially allocated, it starts in the INVALID state.
 * When hse_kvdb_txn_begin() is called with transaction in the INVALID,
 * COMMITTED, or ABORTED states, it moves to the ACTIVE state. It is an error to
 * call the hse_kvdb_txn_begin() function on a transaction in the ACTIVE state.
 * For a transaction in the ACTIVE state, only the functions
 * hse_kvdb_txn_commit(), hse_kvdb_txn_abort(), or hse_kvdb_txn_free() may be
 * called (with the last doing an abort prior to the free).
 *
 * When a transaction becomes ACTIVE, it establishes an ephemeral snapshot view
 * of the state of the KVDB. Any data mutations outside of the transaction's
 * context after that point are not visible to the transaction. Similarly, any
 * mutations performed within the context of the transaction are not visible
 * outside of the transaction unless and until it is committed. All such
 * mutations become visible atomically when the transaction commits.
 *
 * @anchor WRITE_CONFLICT
 *
 * Within a transaction whenever a write operation e.g., put, delete, etc.,
 * encounters a write conflict, that operation returns an error code of
 * ECANCELED. The caller is then expected to re-try the operation in a new
 * transaction, see @ref ERRORS.
 */
/** @{ */

/** @brief Abort/rollback transaction.
 *
 * @warning The call fails if the referenced transaction is not in the ACTIVE
 * state.
 *
 * @note This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p txn must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Allocate transaction object.
 *
 * This object can and should be re-used many times to avoid the overhead of
 * allocation.
 *
 * @note This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 *
 * @remark @p kvdb must not be NULL.
 *
 * @returns The allocated transaction structure.
 */
/* MTF_MOCK */
struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *kvdb);

/** @brief Initiate transaction.
 *
 * @warning The call fails if the transaction handle refers to an ACTIVE
 * transaction.
 *
 * @note This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p txn must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_begin(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Commit all the mutations of the referenced transaction.
 *
 * @warning The call fails if the referenced transaction is not in the ACTIVE
 * state.
 *
 * @note This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p txn must not be NULL.
 *
 * @returns Error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Free transaction object.
 *
 * @warning After invoking this function, calling any other transaction
 * functions with this handle will result in undefined behavior.
 *
 * @note If the transaction handle refers to an ACTIVE transaction, the
 * transaction is aborted prior to being freed.
 *
 * @note This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn: KVDB transaction handle.
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p txn must not be NULL.
 */
/* MTF_MOCK */
void
hse_kvdb_txn_free(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Retrieve the state of the referenced transaction.
 *
 * This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @remark @p kvdb must not be NULL.
 * @remark @p txn must not be NULL.
 *
 * @returns Transaction's state.
 */
/* MTF_MOCK */
enum hse_kvdb_txn_state
hse_kvdb_txn_state_get(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**@} TRANSACTIONS */

/** @defgroup CURSORS Cursors
 * See the concepts and best practices sections on
 * https://hse-project.github.io.
 */
/** @{ */

/** @brief Creates a cursor used to iterate over key-value pairs in a KVS.
 *
 * <b>Non-transactional cursors:</b>
 *
 * If @p txn is NULL, a non-transactional cursor is created. Non-transactional
 * cursors have an ephemeral snapshot view of the KVS at the time it the cursor
 * is created. The snapshot view is maintained for the life of the cursor.
 * Writes to the KVS (put, deletes, etc.) made after the cursor is created will
 * not be visible to the cursor unless hse_kvs_cursor_update_view() is used to
 * obtain a more recent snapshot view. Non-transactional cursors can be used on
 * transactional and non-transactional KVSs.
 *
 * <b>Transactional cursors:</b>
 *
 * If @p txn is not NULL, it must be a valid transaction handle or undefined
 * behavior will result. If it is a valid handle to a transaction in the ACTIVE
 * state, a transactional cursor is created. A transaction cursor's view
 * includes the transaction's writes overlaid on the transaction's ephemeral
 * snapshot view of the KVS. If the transaction is committed or aborted before
 * the cursor is destroyed, the cursor's view reverts to same snaphsot view the
 * transaction had when first became active. The cursor will no longer be able
 * to see the transaction's writes. Calling hse_kvs_cursor_update_view() on a
 * transactional cursor is a no-op and has no effect on the cursor's view.
 * Transactional cursors can only be used on transactional KVSs.
 *
 * <b>Prefix vs non-prefix cursors:</b>
 *
 * Parameters @p filter and @p filter_len can be used to iterate over the subset
 * of keys in the KVS whose first @p filter_len bytes match the @p filter_len
 * bytes pointed to by @p filter.
 *
 * A prefix cursor is created when:
 * @li KVS was created with @p pfx_len > 0 (i.e., it is a prefix KVS), and
 * @li @p filter != NULL and @p filter_len >= @p pfx_len.
 *
 * Otherwise, a non-prefix cursor is created.
 *
 * Applications should arrange their key-value data to avoid the need for
 * non-prefix cursors as they are significantly slower and more
 * resource-intensive than prefix cursors. Note that simply using a filter
 * doesn't create a prefix cursor -- it must meet the two conditions listed
 * above.
 *
 * @note This function is thread safe.
 *
 * <b>Flags:</b>
 * @arg HSE_CURSOR_CREATE_REV - Iterate in reverse lexicographical order.
 *
 * @param kvs: KVS to iterate over, handle from hse_kvdb_kvs_open().
 * @param flags: Flags for operation specialization.
 * @param txn: Transaction context (optional).
 * @param filter: Iteration limited to keys matching this prefix filter
 * (optional).
 * @param filter_len: Length of filter (optional).
 * @param[out] cursor: Cursor handle.
 *
 * @remark @p kvs must not be NULL.
 * @remark @p cursor must not be NULL.
 *
 * @returns Error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *        kvs,
    unsigned int            flags,
    struct hse_kvdb_txn *   txn,
    const void *            filter,
    size_t                  filter_len,
    struct hse_kvs_cursor **cursor);

/** @brief Destroy cursor.
 *
 * @warning After invoking this function, calling any other cursor functions
 * with this handle will result in undefined behavior.
 *
 * @note Cursor objects are not thread safe.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 *
 * @remark @p cursor must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

/** @brief Iteratively access the elements pointed to by the cursor.
 *
 * Read a key-value pair from the cursor, advancing the cursor past its current
 * location. If the argument @p val is NULL, only the key is read.
 *
 * @note If the cursor is at EOF, attempts to read from it will not change the
 * state of the cursor.
 * @note Cursor objects are not thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 * @param flags: Flags for operation specialization.
 * @param[out] key: Next key in sequence.
 * @param[out] key_len: Length of @p key.
 * @param[out] val: Next value in sequence.
 * @param[out] val_len: Length of @p val.
 * @param[out] eof: If true, no more key-value pairs in sequence.
 *
 * @remark @p cursor must not be NULL.
 * @remark @p key must not be NULL.
 * @remark @p key_len must not be NULL.
 * @remark @p val must not be NULL.
 * @remark @p val_len must not be NULL.
 * @remark @p eof must not be NULL.
 *
 * @returns Error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_read(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void **          key,
    size_t *               key_len,
    const void **          val,
    size_t *               val_len,
    bool *                 eof);

/** @brief Iteratively access the elements pointed to by the cursor.
 *
 * Read a key-value pair from the cursor, advancing the cursor past its current
 * location. The key-value pair will be copied into the user's buffer(s). If the
 * argument @p valbuf is NULL, only the key is read.
 *
 * @note If the cursor is at EOF, attempts to read from it will not change the
 * state of the cursor.
 * @note Cursor objects are not thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 * @param flags: Flags for operation specialization.
 * @param[in,out] keybuf: Buffer into which the next key will be copied.
 * @param keybuf_sz: Size of @p keybuf.
 * @param[out] key_len: Length of the key.
 * @param[in,out] valbuf: Buffer into which the next key's value will be copied.
 * @param valbuf_sz: Size of @p valbuf
 * @param[out] val_len: Length of @p val.
 * @param[out] eof: If true, no more key-value pairs in sequence.
 *
 * @remark @p cursor must not be NULL.
 * @remark @p key must not be NULL.
 * @remark @p key_len must not be NULL.
 * @remark @p val must not be NULL.
 * @remark @p val_len must not be NULL.
 * @remark @p eof must not be NULL.
 *
 * @returns Error status
 */
hse_err_t
hse_kvs_cursor_read_copy(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    void *                 keybuf,
    size_t                 keybuf_sz,
    size_t *               key_len,
    void *                 valbuf,
    size_t                 valbuf_sz,
    size_t *               val_len,
    bool *                 eof);

/** @brief Move the cursor to point at the key-value pair at or closest to @p
 * key.
 *
 * The next hse_kvs_cursor_read() will start at this point. Both @p found and @p
 * found_len must be non-NULL for that functionality to work.
 *
 * @note Cursor objects are not thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 * @param flags: Flags for operation specialization.
 * @param key: Key to find.
 * @param key_len: Length of @p key.
 * @param[out] found: If non-NULL, referent point to next key in sequence
 * (optional).
 * @param found_len: If @p found is non-NULL, referent is length of @p found
 * key.
 *
 * @remark @p cursor must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_seek(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void *           key,
    size_t                 key_len,
    const void **          found,
    size_t *               found_len);

/** @brief Move the cursor to the closest match to key, gated by the given
 * filter.
 *
 * Keys read from this cursor will belong to the closed interval defined by the
 * given filter: [@p filt_min, @p filt_max]. For KVSs storing segmented keys,
 * performance will be enhanced when @p filt_min_len and @p filt_max_len are
 * greater than or equal to the KVS key prefix length. Both @p found and @p
 * found_len must be non-NULL for that functionality to work.
 *
 * @note This is only supported for forward cursors.
 * @note Cursor objects are not thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 * @param flags: Flags for operation specialization.
 * @param filt_min: Filter minimum.
 * @param filt_min_len: Length of @p filt_min.
 * @param filt_max: Filter maximum.
 * @param filt_max_len: Length of @p filt_max.
 * @param[out] found: If non-NULL, referent points to next key in sequence
 * (optional).
 * @param[out] found_len: If non-NULL, referent is length of @p found key
 * (optional).
 *
 * @remark @p cursor must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_seek_range(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void *           filt_min,
    size_t                 filt_min_len,
    const void *           filt_max,
    size_t                 filt_max_len,
    const void **          found,
    size_t *               found_len);

/** @brief Update a the cursor view.
 *
 * This operation updates the snapshot view of a non-transaction cursor. It is a
 * no-op on transaction cursors.
 *
 * @note Cursor objects are not thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - Reserved for future use.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 * @param flags: Flags for operation specialization.
 *
 * @remark @p cursor must not be NULL.
 *
 * @returns Error status.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_update_view(struct hse_kvs_cursor *cursor, unsigned int flags);

/**@} CURSORS */

#pragma GCC visibility pop

#if HSE_MOCKING
#include "hse_ut.h"
#endif /* HSE_MOCKING */

#ifdef __cplusplus
}
#endif

#endif
