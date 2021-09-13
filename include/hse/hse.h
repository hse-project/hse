/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/** @file hse.h
 */

#ifndef HSE_KVDB_API_H
#define HSE_KVDB_API_H

/* MTF_MOCK_DECL(hse) */

/** @mainpage Overview
 *
 * The documentation here is geared towards describing the structure of the HSE API and
 * the specifics of each entry point's operation.  Refer to
 * https://hse-project.github.io/2.x/dev/concepts/ for a conceptual overview of HSE.
 *
 * <h3>Terminology</h3>
 *
 * @arg <b>KVS</b> - Key-value store, containing zero or more key-value pairs
 *
 * @arg <b>KVDB</b> - Key-value database, comprised of one or more KVSs and defining a
 * transaction domain
 *
 * @arg <b>key</b> - A byte string used to uniquely identify values for storage, retrieval, and
 * deletion in a KVS
 *
 * @arg <b>segmented key</b>- A key that is logically divided into N segments (N >= 2),
 * arranged to group related key-value pairs when keys are sorted lexicographically
 *
 * @arg <b>key prefix</b> - For segmented keys, the first K segments (1 <= K < N).
 *
 * @arg <b>key prefix length</b> - The length of a key prefix (bytes)
 */

/** @page examples Examples
 * See the samples directory in the source tree for examples. Here is a simple one.
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

#ifdef __has_attribute
#  if __has_attribute(visibility)
#    define HSE_EXPORT __attribute__((visibility("default")))
#  else
#    define HSE_EXPORT
#  endif
#else
#  define HSE_EXPORT
#endif

#ifdef HSE_EXPORT_EXPERIMENTAL
#undef HSE_EXPORT_EXPERIMENTAL
#define HSE_EXPORT_EXPERIMENTAL HSE_EXPORT
#else
#define HSE_EXPORT_EXPERIMENTAL
#endif

/** @addtogroup ERROR_HANDLING HSE Return Codes
 * @{
 * Describes the HSE API return code type and associated utilities.
 */

/** @brief Return an hse_err_t value's string representation.
 *
 * The hse_err_t scalar value @p err is decoded into a NULL-terminated string
 * representation giving more information about the error and where it occurred. The
 * string will be truncated if @p buf_len is too small (a @p buf_len value of 128 is
 * sufficient to avoid truncation of most error strings). This function is thread safe.
 *
 * @param err:      Error value returned from an HSE API function.
 * @param buf:      Buffer to hold the formatted string.
 * @param buf_len:  Length of buffer.
 *
 * @returns The number of characters (excluding the terminating null byte) which would
 * have been written to the final string if enough space had been available.
 */
HSE_EXPORT size_t
hse_strerror(hse_err_t err, char *buf, size_t buf_len);

/** @brief Return an hse_err_t value's errno representation.
 *
 * The hse_err_t scalar value @p err is translated into its errno equivalent. This
 * function is thread safe.
 *
 * @param err: Error value returned from an HSE API function.
 *
 * @returns The error's errno equivalent.
 */
HSE_EXPORT int
hse_err_to_errno(hse_err_t err);

/**@} ERROR_HANDLING */

/** @defgroup INIT Initialization Routines
 * @{
 */

/** @brief Initialize the HSE subsystem.
 *
 * This function initializes a range of different internal HSE structures. It must be
 * called before any other HSE functions are used. It is not thread safe and is
 * idempotent.
 *
 * @param config: Path to a global configuration file.
 * @param paramc: Number of initialization parameters in @p paramv.
 * @param paramv: List of parameters in key=value format.
 *
 * @returns Error status
 */
HSE_EXPORT hse_err_t
hse_init(const char *config, size_t paramc, const char *const *paramv);

/** @brief Shutdown the HSE subsystem.
 *
 * This function cleanly finalizes a range of different internal HSE structures. It
 * should be called prior to application exit and is not thread safe. After it is
 * invoked (and even before it returns), calling any other HSE functions will result in
 * undefined behavior. This function is not thread safe.
 */
HSE_EXPORT void
hse_fini(void);

/** @} INIT */


/** @defgroup LIFECYCLE Primary Lifecycle Functions
 * @{
 * Functions that manage HSE objects.
 */

/** @brief Create a KVDB.
 *
 * This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory, NULL means current working directory.
 * @param paramc:    Number of configuration parameters in @p paramv.
 * @param paramv:    List of parameters in key=value format.
 *
 * @returns The function's error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_create(const char *kvdb_home, size_t paramc, const char *const *paramv);

/** @brief Drop a KVDB.
 *
 * It is an error to call this function on a KVDB that is open. This function is not
 * thread safe.
 *
 * @param kvdb_home: KVDB home directory, NULL means current working directory.
 *
 * @returns Error status
 */
HSE_EXPORT hse_err_t
hse_kvdb_drop(const char *kvdb_home);

/** @brief Open a KVDB.
 *
 * The KVDB must already exist and the client must have permission to use it. This
 * function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory, NULL means current working directory
 * @param paramc:    Number of configuration parameters in @p paramv.
 * @param paramv:    List of parameters in key=value format.
 * @param[out] kvdb: Handle to access the opened KVDB.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_open(
    const char *       kvdb_home,
    size_t             paramc,
    const char *const *paramv,
    struct hse_kvdb ** kvdb);

/** @brief Close a KVDB.
 *
 * No client thread may enter the HSE KVDB API with the referenced KVDB after this
 * function starts. This function is not thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_close(struct hse_kvdb *kvdb);

/** @brief Get the names of the KVSs within the given KVDB.
 *
 * Key-value stores (KVSs) are opened by name. This function allocates a vector of
 * allocated strings, each containing the NULL-terminated name of a KVS. The memory must
 * be freed via hse_kvdb_kvs_names_free(). This function is thread safe.
 *
 * Example Usage:
 *
 * @code{.c}
 *     int     namec, i, rc;
 *     char  **namev;
 *
 *     rc = hse_kvdb_kvs_names_get(kvdb, &namec, &namev);
 *     if (!rc) {
 *         for (i = 0; i < namec; i++)
 *             printf("%s\n", namev[i]);
 *     }
 *     hse_kvdb_kvs_names_free(namev);
 * @endcode
 *
 * @param kvdb:       KVDB handle from hse_kvdb_open().
 * @param[out] namec: Number of KVSs in the KVDB.
 * @param[out] namev: Vector of KVSs. Allocated by the function.
 *
 * @returns Error status
 *
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_kvs_names_get(struct hse_kvdb *kvdb, size_t *namec, char ***namev);

/** @brief Free the names collection obtained through hse_kvdb_kvs_names_get().
 *
 * This function is thread safe.
 *
 * @param kvdb:  KVDB handle from hse_kvdb_open().
 * @param namev: Vector of KVS names that hse_kvdb_kvs_names_get() output.
 */
HSE_EXPORT void
hse_kvdb_kvs_names_free(struct hse_kvdb *kvdb, char **namev);

/** @brief Create a KVS within the referenced KVDB.
 *
 * If the KVS will store segmented keys then the parameter "pfx_len" should be set to
 * the desired key prefix length.  An error will result if there is already a KVS with the
 * given name. This function is not thread safe.
 *
 * @param kvdb:     KVDB handle from hse_kvdb_open().
 * @param kvs_name: KVS name (NULL terminated, strlen() < HSE_KVS_NAME_LEN_MAX)
 * @param paramc:   Number of configuration parameters in @p paramv.
 * @param paramv:   List of parameters in key=value format.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_kvs_create(
    struct hse_kvdb *  kvdb,
    const char *       kvs_name,
    size_t             paramc,
    const char *const *paramv);

/** @brief Drop a KVS from the referenced KVDB.
 *
 * It is an error to call this function on a KVS that is open. This function is not
 * thread safe.
 *
 * @param kvdb:     KVDB handle from hse_kvdb_open()
 * @param kvs_name: KVS name (NULL-terminated string)
 *
 * @returns The function's error status
 */
HSE_EXPORT hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *kvdb, const char *kvs_name);

/** @brief Open a KVS in a KVDB.
 *
 * This function is not thread safe.
 *
 * @param handle:       KVDB handle from hse_kvdb_open().
 * @param kvs_name:     KVS name (NULL terminated string).
 * @param paramc:       Number of configuration parameters in @p paramv.
 * @param paramv:       List of parameters in key=value format.
 * @param[out] kvs_out: Handle to access the opened KVS.
 *
 * @returns The function's error status
 */
HSE_EXPORT hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *  handle,
    const char *       kvs_name,
    const size_t       paramc,
    const char *const *paramv,
    struct hse_kvs **  kvs_out);

/** @brief Close an open KVS.
 *
 * No client thread may enter the HSE KVDB API with the referenced KVS after this
 * function starts. This function is not thread safe.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open().
 *
 * @returns The function's error status
 */
HSE_EXPORT hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *kvs);

/**@} LIFECYCLE */

/** @defgroup CRUD Create, Read, Update and Delete (CRUD) Functions
 * @{
 */

/** @brief Put a key-value pair into KVS.
 *
 * If the key already exists in the KVS then the value is effectively overwritten. The
 * key length must be in the range [1, HSE_KVS_KEY_LEN_MAX] while the value length must be
 * in the range [0, HSE_KVS_VALUE_LEN_MAX]. See the section on transactions for information
 * on how puts within transactions are handled. This function is thread safe.
 *
 * The HSE KVDB attempts to maintain reasonable QoS and for high-throughput clients this
 * results in very short sleep's being inserted into the put path. For some kinds of
 * data (e.g., control metadata) the client may wish to not experience that delay. For
 * relatively low data rate uses, the caller can set the HSE_FLAG_PUT_PRIORITY flag
 * for an hse_kvs_put(). Care should be taken when doing so to ensure that the
 * system does not become overrun. As a rough approximation, doing 1M priority puts per
 * second marked as PRIORITY is likely an issue. On the other hand, doing 1K small puts
 * per second marked as PRIORITY is almost certainly fine.
 *
 * If compression is enabled for the given kvs, then hse_kvs_put() will attempt to
 * compress the value unless the HSE_FLAG_PUT_VCOMP_OFF flag is given.  Otherwise,
 * the HSE_FLAG_PUT_VCOMP_OFF flag is ignored.
 *
 * <b>Flags:</b>
 * @arg HSE_FLAG_PUT_PRIORITY - Operation will not be throttled
 * @arg HSE_FLAG_PUT_VCOMP_OFF - Value will not be compressed
 *
 * @param kvs:     KVS handle from hse_kvdb_kvs_open().
 * @param flags:   Flags for operation specialization.
 * @param txn:     Transaction context.
 * @param key:     Key to put into kvs.
 * @param key_len: Length of key.
 * @param val:     Value associated with key.
 * @param val_len: Length of value.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_put(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         key,
    size_t               key_len,
    const void *         val,
    size_t               val_len);

/** @brief Retrieve the value for a given key from KVS.
 *
 * If the key exists in the KVS then the referent of "found" is set to true. If the
 * caller's value buffer is large enough then the data will be returned. Regardless, the
 * actual length of the value is placed in "val_len". See the section on transactions for
 * information on how gets within transactions are handled. This function is thread
 * safe.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param kvs:          KVS handle from hse_kvdb_kvs_open().
 * @param flags:        Flags for operation specialization.
 * @param txn:          Transaction context.
 * @param key:          Key to get from kvs.
 * @param key_len:      Length of key.
 * @param[out] found:   Whether or not key was found.
 * @param[out] buf:     Buffer into which the value associated with key will be copied.
 * @param buf_len:      Length of buffer.
 * @param[out] val_len: Actual length of value if key was found.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
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

/** @brief Delete the key and its associated value from KVS.
 *
 * It is not an error if the key does not exist within the KVS. See the section on
 * transactions for information on how deletes within transactions are handled. This
 * function is thread safe.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param kvs:     KVS handle from hse_kvdb_kvs_open()
 * @param flags:   Flags for operation specialization
 * @param txn:     Transaction context (optional)
 * @param key:     Key to be deleted from kvs
 * @param key_len: Length of key
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         key,
    size_t               key_len);

/** @brief Delete all key-value pairs matching the key prefix from a KVS storing segmented keys.
 *
 * This interface is used to delete an entire range of segmented keys. To do this
 * the caller passes a filter with a length equal to the KVS's key prefix length. It is
 * not an error if no keys exist matching the filter. If there is a filtered iteration
 * in progress, then that iteration can fail if hse_kvs_prefix_delete() is called with
 * a filter matching the iteration. This function is thread safe.
 *
 * If hse_kvs_prefix_delete() is called from a transaction context, it affects no
 * key-value mutations that are part of the same transaction. Stated differently, for
 * KVS commands issued within a transaction, all calls to hse_kvs_prefix_delete() are
 * treated as though they were issued serially at the beginning of the transaction
 * regardless of the actual order these commands appeared in.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param kvs:              KVS handle from hse_kvdb_kvs_open().
 * @param flags:            Flags for operation specialization.
 * @param txn:              Transaction context (optional).
 * @param filter:           Filter for keys to delete.
 * @param filter_len:       Filter length.
 * @param[out] kvs_pfx_len: If specified, this will be set to the KVS's prefix length.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         filter,
    size_t               filter_len,
    size_t *             kvs_pfx_len);

#ifdef HSE_EXPERIMENTAL
/**
 * Probe for a prefix
 *
 * Outputs how many matches were encountered - zero, one or multiple. This function is
 * thread safe.
 *
 * <b>Flags:</b>
 * @arg  @0 - reserved for future use
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context
 * @param pfx: Prefix to be probed
 * @param pfx_len: Length of @p pfx
 * @param[out] found: Zero, one or multiple matches seen
 * @param keybuf: Buffer which will be populated with contents of first seen key
 * @param keybuf_sz: Size of @p keybuf
 * @param[out] key_len: Length of first seen key
 * @param valbuf: Buffer which will be populated with value for @keybuf
 * @param valbuf_sz: Size of @p valbuf
 * @param[out] val_len: Length of the value seen
 * @returns The function's error status
 */
HSE_EXPORT_EXPERIMENTAL hse_err_t
hse_kvs_prefix_probe(
    struct hse_kvs *            kvs,
    unsigned int                flags,
    struct hse_kvdb_txn        *txn,
    const void *                pfx,
    size_t                      pfx_len,
    enum hse_kvs_pfx_probe_cnt *found,
    void *                      keybuf,
    size_t                      keybuf_sz,
    size_t *                    key_len,
    void *                      valbuf,
    size_t                      valbuf_sz,
    size_t *                    val_len);
#endif

/**@} CRUD */


/** @defgroup TXN Transaction Functions
 * The HSE KVDB provides transactions with operations spanning KVSs within a single
 * KVDB.  These transactions have snapshot isolation (a specific form of MVCC) with the
 * normal semantics (see "Concurrency Control and Recovery in Database Systems" by PA
 * Bernstein).
 *
 * One unusual aspect of the API as it relates to transactions is that the data object
 * that is used to hold client-level transaction state is allocated separately from the
 * transaction being initiated. As a result, the same object handle should be reused
 * again and again.
 *
 * In addition, there is very limited coupling between threading and transactions. A
 * single thread may have many transactions in flight simultaneously. Also operations
 * within a transaction can be performed by multiple threads. The latter mode of
 * operation must currently restrict calls so that only one thread is actively
 * performing an operation in the context of a particular transaction at any particular
 * time.
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

 * When a transaction is initially allocated, it starts in the INVALID state. When
 * hse_kvdb_txn_begin() is called with transaction in the INVALID, COMMITTED, or ABORTED
 * states, it moves to the ACTIVE state. It is an error to call the hse_kvdb_txn_begin()
 * function on a transaction in the ACTIVE state. For a transaction in the ACTIVE state,
 * only the functions hse_kvdb_txn_commit(), hse_kvdb_txn_abort(), or
 * hse_kvdb_txn_free() may be called (with the last doing an abort prior to the free).
 *
 * When a transaction becomes ACTIVE, it establishes an ephemeral snapshot view of the
 * state of the KVDB. Any data mutations outside of the transaction's context after that
 * point are not visible to the transaction. Similarly, any mutations performed within
 * the context of the transaction are not visible outside of the transaction unless and
 * until it is committed. All such mutations become visible atomically when the
 * transaction commits.
 *
 * @anchor WRITE_CONFLICT
 * Within a transaction whenever a write operation e.g., put, delete, etc., encounters a
 * write conflict, that operation returns an error code of ECANCELED. The caller is then
 * expected to re-try the operation in a new transaction, see @ref ERROR_HANDLING.
 */
/** @{ */

/** @brief Allocate transaction object.
 *
 * This object can and should be re-used many times to avoid the overhead of
 * allocation. This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 *
 * @returns The allocated transaction structure.
 */
/* MTF_MOCK */
HSE_EXPORT struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *kvdb);

/** @brief Free transaction object.
 *
 * If the transaction handle refers to an ACTIVE transaction, the transaction is aborted
 * prior to being freed. This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn:  KVDB transaction handle.
 */
/* MTF_MOCK */
HSE_EXPORT void
hse_kvdb_txn_free(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Initiate transaction.
 *
 * The call fails if the transaction handle refers to an ACTIVE transaction. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn:  KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @returns The function's error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_txn_begin(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Commit all the mutations of the referenced transaction.
 *
 * The call fails if the referenced transaction is not in the ACTIVE state. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn:  KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Abort/rollback transaction.
 *
 * The call fails if the referenced transaction is not in the ACTIVE state. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn:  KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/** @brief Retrieve the state of the referenced transaction.
 *
 * This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open().
 * @param txn:  KVDB transaction handle from hse_kvdb_txn_alloc().
 *
 * @returns The transaction's state
 */
/* MTF_MOCK */
HSE_EXPORT enum hse_kvdb_txn_state
hse_kvdb_txn_state_get(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**@} TXN */


/** @defgroup CURSOR Cursor Functions
 * See the concept and best practices sections on the HSE project site at
 * https://hse-project.github.io/2.x/dev/concepts/
 */
/** @{ */

/** @brief Creates a cursor used to iterate over key-value pairs in a KVS.
 *
 * <b>Non-transaction cursors:</b>
 *
 * If @p txn is NULL, a non-transaction cursor is created.  Non-transaction cursors have
 * an ephemeral snapshot view of the KVS at the time it the cursor is created.  The
 * snapshot view is maintained for the life of the cursor.  Writes to the KVS (put,
 * deletes, etc.) made after the cursor is created will not be visible to the cursor
 * unless hse_kvs_cursor_update_view() is used to obtain a more recent snapshot view.  Non
 * transaction cursors can be used on transaction and non-transaction KVSs.
 *
 * <b>Transaction cursors:</b>
 *
 * If @p txn is not NULL, it must be a valid transaction handle or undefined behavior will
 * result.  If it is a valid handle to a transaction in the ACTIVE state, a transaction
 * cursor is created.  A transaction cursor's view includes the transaction's writes
 * overlaid on the transaction's ephemeral snapshot view of the KVS.  If the transaction
 * is committed or aborted before the cursor is destroyed, the cursor's view reverts to
 * same snaphsot view the transaction had when first became active. The cursor will no
 * longer be able to see the transaction's writes.  Calling hse_kvs_cursor_update_view()
 * on a transaction cursor is a no-op and has no effect on the cursor's view.  Transaction
 * cursors can only be used on transaction KVSs.
 *
 * <b>Prefix vs non-prefix cursors:</b>
 *
 * Parameters @p filter and @p filter_len can be used to iterate over the subset of keys in
 * the KVS whose first @p filter_len bytes match the @p filter_len bytes pointed to by @p
 * filter.
 *
 * A prefix cursor is created when:
 * @li KVS was created with @p pfx_len > 0 (i.e., it is a prefix KVS), and
 * @li @p filter != NULL and @p filter_len >= @ pfx_len.
 *
 * Otherwise, a non-prefix cursor is created.
 *
 * Applications should arrange their key-value data to avoid the need for non-prefix
 * cursors as they are significantly slower and more resource-intensive than prefix cursors.
 * Note that simply using a filter doesn't create a prefix cursor -- it must meet the
 * two conditions listed above.
 *
 * <b>Flags:</b>
 * @arg HSE_FLAG_CURSOR_REVERSE - iterate in reverse lexicographic order
 *
 * This function is thread safe across disparate cursors.
 *
 * @param kvs:         KVS to iterate over, handle from hse_kvdb_kvs_open().
 * @param flags:       Flags for operation specialization.
 * @param txn:         Transaction context (optional).
 * @param filter:      Iteration limited to keys matching this prefix filter (optional).
 * @param filter_len:  Length of filter (optional).
 * @param[out] cursor: Cursor handle.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *        kvs,
    unsigned int            flags,
    struct hse_kvdb_txn *   txn,
    const void *            filter,
    size_t                  filter_len,
    struct hse_kvs_cursor **cursor);

/** @brief Update a plain cursor or modify any cursor.
 *
 * This operation updates the snapshot view of a non-transaction cursor.  It is a no-op on
 * transaction cursors.  This function is thread safe across disparate cursors.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 * @param flags:  Flags for operation specialization.
 *
 * @returns The function's error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_cursor_update_view(struct hse_kvs_cursor *cursor, unsigned int flags);

/** @brief Move the cursor to point at the key-value pair at or closest to "key".
 *
 * The next hse_kvs_cursor_read() will start at this point. Both "found" and "found_len"
 * must be non-NULL for that functionality to work. This function is thread safe across
 * disparate cursors.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param cursor:    Cursor handle from hse_kvs_cursor_create().
 * @param flags:     Flags for operation specialization.
 * @param key:       Key to find.
 * @param key_len:   Length of key.
 * @param found:     If non-NULL, referent point to next key in sequence (optional).
 * @param found_len: If "found" is non-NULL, referent is length of "found" key.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_cursor_seek(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void *           key,
    size_t                 key_len,
    const void **          found,
    size_t *               found_len);

/** @brief Move the cursor to the closest match to key, gated by the given filter.
 *
 * Keys read from this cursor will belong to the closed interval defined by the given
 * filter: [@p filt_min, @p filt_max]. For KVSs storing segmented keys, performance
 * will be enhanced when @p filt_min_len and @p filt_max_len are greater than or equal to
 * the KVS key prefix length.  Both @p found and @p found_len must be non-NULL for that
 * functionality to work. This function is thread safe across disparate cursors.
 *
 * Note: this is only supported for forward cursors.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param cursor:         Cursor handle from hse_kvs_cursor_create().
 * @param flags:          Flags for operation specialization.
 * @param filt_min:       Filter minimum.
 * @param filt_min_len:   Length of filter minimum.
 * @param filt_max:       Filter maximum.
 * @param filt_max_len:   Length of filter maximum.
 * @param[out] found:     If non-NULL, referent points to next key in sequence (optional).
 * @param[out] found_len: If non-NULL, referent is length of "found" key (optional).
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_cursor_seek_range(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void *           filt_min,
    size_t                 filt_min_len,
    const void *           filt_max,
    size_t                 filt_max_len,
    const void **          found,
    size_t *               found_len);

/** @brief Iteratively access the elements pointed to by the cursor.
 *
 * Read a key-value pair from the cursor, advancing the cursor past its current location. If
 * the cursor is at EOF, attempts to read from it will not change the state of the
 * cursor. This function is thread safe across disparate cursors.
 *
 * <b>Flags:</b>
 * @arg 0 - reserved for future use
 *
 * @param cursor:       Cursor handle from hse_kvs_cursor_create().
 * @param flags:        Flags for operation specialization.
 * @param[out] key:     Next key in sequence.
 * @param[out] key_len: Length of key.
 * @param[out] val:     Next value in sequence.
 * @param[out] val_len: Length of value.
 * @param[out] eof:     If true, no more key-value pairs in sequence.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_cursor_read(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void **          key,
    size_t *               key_len,
    const void **          val,
    size_t *               val_len,
    bool *                 eof);

/** @brief Destroy cursor.
 *
 * This function is thread safe.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create().
 *
 * @returns The function's error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

/**@} CURSOR */


/** @defgroup DSTATE Data State Management Functions
 * @{
 */

/** @brief Sync data in all of the referenced KVDB's KVSs to stable media and return.
 *
 * <b>Flags:</b>
 * @arg HSE_KVDB_SYNC_ASYNC - Return immediately after initiating operation instead
 *                            of waiting for completion.
 *
 * @param kvdb:  KVDB handle from hse_kvdb_open().
 * @param flags: Flags for operation specialization.
 *
 * @returns Error status
 */
/* MTF_MOCK */
HSE_EXPORT hse_err_t
hse_kvdb_sync(struct hse_kvdb *kvdb, unsigned int flags);

/**@} DSTATE */


/** @defgroup LIMITS Limits
 * @{
 */

/* empty here to maintain the order in doxygen output, see include/hse/limits.h */

/** @} LIMITS */

#ifdef HSE_EXPERIMENTAL
/**
 * Request a data compaction operation
 *
 * In managing the data within an HSE KVDB, there are maintenance activities that occur
 * as background processing. The application may be aware that it is advantageous to do
 * enough maintenance now for the database to be as compact as it ever would be in
 * normal operation. To achieve this, the client calls this function in the following
 * fashion:
 *
 *     hse_kvdb_compact(<kvdb handle>, HSE_KVDB_COMPACT_SAMP_LWM);
 *
 * To cancel an ongoing compaction request for a KVDB:
 *
 *     hse_kvdb_compact(<kvdb handle>, HSE_FLAG_KVDB_COMPACT_CANCEL);
 *
 * See the function hse_kvdb_compact_status_get(). This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param flags: Compaction flags
 * @returns The function's error status
 */
HSE_EXPORT_EXPERIMENTAL hse_err_t
hse_kvdb_compact(struct hse_kvdb *kvdb, unsigned int flags);

/**
 * Get status of an ongoing compaction activity
 *
 * The caller can examine the fields of the hse_kvdb_compact_status struct to determine
 * the current state of maintenance compaction. This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param[out] status: Status of compaction request
 * @returns The function's error status
 */
HSE_EXPORT_EXPERIMENTAL hse_err_t
hse_kvdb_compact_status_get(struct hse_kvdb *kvdb, struct hse_kvdb_compact_status *status);
#endif

/**
 * Get storage config and stats
 *
 * Obtain the space usage statistics for a specified kvdb.
 * This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param[out] info: KVDB storage config and stats
 * @returns The function's error status
 */
HSE_EXPORT hse_err_t
hse_kvdb_storage_info_get(struct hse_kvdb *kvdb, struct hse_kvdb_storage_info *info);

/**
 * Add a new media class storage to an existing offline KVDB
 * This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory, NULL means current working directory.
 * @param paramc:    Number of configuration parameters in @p paramv.
 * @param paramv:    List of KVDB create-time parameters in key=value format.
 *
 * @returns The function's error status
 */
HSE_EXPORT hse_err_t
hse_kvdb_storage_add(const char *kvdb_home, size_t paramc, const char *const *paramv);

#undef HSE_EXPORT_EXPERIMENTAL
#undef HSE_EXPORT

#if HSE_MOCKING
/* This is a complete hack because of the way mocks are generated. HSE_EXPORT
 * gets pulled as part of the function declaration when creating the function
 * pointers types for each mocked function.
 */
#define HSE_EXPORT
#define HSE_EXPORT_EXPERIMENTAL
#include "hse_ut.h"
#undef HSE_EXPORT_EXPERIMENTAL
#undef HSE_EXPORT
#endif /* HSE_MOCKING */

#ifdef __cplusplus
}
#endif

#endif
