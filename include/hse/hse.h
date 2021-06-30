/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

/** @file hse.h
 */

#ifndef HSE_KVDB_API_H
#define HSE_KVDB_API_H

/* MTF_MOCK_DECL(hse) */

/*! @mainpage Overview
 *
 * The HSE library is generally described in other places. The documentation here is
 * geared towards describing the structure of the HSE API and the specifics of each
 * entry point's operation.
 *
 * Terminology:
 *
 *     KVS               - Key-value store, containing zero or more key-value (KV)
 *                         pairs
 *
 *     KVDB              - Key-value database, comprised of one or more KVSs and
 *                         defining a transaction domain
 *
 *     key               - A byte string used to uniquely identify values for
 *                         storage, retrieval, and deletion in a KVS
 *
 *     multi-segment key - A key that is logically divided into N segments (N >= 2),
 *                         arranged to group related KV pairs when keys are sorted
 *                         lexicographically
 *
 *     key prefix        - For multi-segment keys, the first K segments (1 <= K < N)
 *                         that group related KV pairs when keys are sorted lexi-
 *                         cographically
 *
 *     key prefix length - For multi-segment keys, the length of a key prefix (bytes)
 *
 *     unsegmented key   - A key that is not logically divided into segments
 */

#include <hse/hse_limits.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#ifdef __cplusplus
extern "C" {
#endif

/** @name Type Declarations / Shared Structures / Macros
 *        =====================================================
 * @{
 */

/**
 * These types are generally opaque handles that a client obtains by using library
 * functions. A client uses these handles to exercise more fine-grained
 * functionality. For example a "struct hse_kvdb" is the handle for a key-value database
 * that one obtains by calling hse_kvdb_open().
 *
 * @typedef hse_err_t
 * @brief Generic return type for the HSE library
 *
 * If this scalar quantity is 0 then the call succeeded. If it is non-zero then the
 * 64-bit quantity can be used by the client in two ways: (1) call hse_err_to_errno() to
 * get a mapping to a POSIX errno value, and (2) call hse_err_to_string() to get a
 * textual reference about what error occurred and where.
 *
 * @typedef hse_kvdb
 * @brief Opaque structure, a pointer to which is a handle to an HSE key-value
 *        database (KVDB)
 *
 * @typedef hse_kvs
 * @brief Opaque structure, a pointer to which is a handle to an HSE key-value
 *        store within a KVDB (KVS)
 *
 * @typedef hse_kvs_cursor
 * @brief Opaque structure, a pointer to which is a handle to a cursor within
 *        a KVS
 *
 * @typedef hse_kvdb_txn
 * @brief Opaque structure, a pointer to which is a handle to a transaction
 *        within a KVDB.
 */

typedef uint64_t hse_err_t;
struct hse_kvdb;
struct hse_kvs;
struct hse_kvs_cursor;
struct hse_kvdb_txn;

#define HSE_FLAG_NONE 0

/**@}*/

#pragma GCC visibility push(default)

/** @name Utility Routines
 *        =====================================================
 * @{
 */

/**
 * Initialize the HSE subsystem
 *
 * This function initializes a range of different internal HSE structures. It must be
 * called before any other HSE functions are used. It is not thread safe and is
 * idempotent.
 */
hse_err_t
hse_init(size_t paramc, const char *const *paramv);

/**
 * Shutdown the HSE subsystem
 *
 * This function cleanly finalizes a range of different internal HSE structures. It
 * should be called prior to application exit and is not thread safe. After it is
 * invoked (and even before it returns), calling any other HSE functions will result in
 * undefined behavior. This function is not thread safe.
 */
void
hse_fini(void);

/**
 * Return an hse_err_t value's string representation
 *
 * The hse_err_t scalar value "err" is decoded into a string representation giving more
 * information about the error and where it occurred. This function is thread safe.
 *
 * @param err:      Error value returned from an HSE API function
 * @param buf:      Buffer to hold the formatted string
 * @param buf_len:  Length of buffer
 * @param need_len: [out] If non-NULL, the referent size_t will be the needed
 *                  buffer length
 * @return The error's NULL-terminated string representation, possibly truncated
 */
char *
hse_err_to_string(hse_err_t err, char *buf, size_t buf_len, size_t *need_len);

/**
 * Return an hse_err_t value's errno representation
 *
 * The hse_err_t scalar value "err" is translated into its errno equivalent. This
 * function is thread safe.
 *
 * @param err: Error value returned from an HSE API function
 * @return The error's errno equivalent
 */
int
hse_err_to_errno(hse_err_t err);

/**@}*/

/** @name Primary Lifecycle Functions
 *        =====================================================
 * @{
 */

/**
 * Create a new KVDB instance
 *
 * This function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory, NULL means current working directory
 * @param paramc: Number of configuration parameters in \p paramv
 * @param paramv: List of parameters in key=value format
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_create(const char *kvdb_home, size_t paramc, const char *const *paramv);

/**
 * Remove a KVDB
 *
 * It is an error to call this function on a KVDB that is open. This function is not
 * thread safe.
 *
 * @param kvdb_home: KVDB home directoryy, NULL means current working directory
 * @param paramc: Number of configuration parameters in \p paramv
 * @param paramv: List of parameters in key=value format
 * @return The function's error status
 */
hse_err_t
hse_kvdb_drop(const char *kvdb_home, size_t paramc, const char *const *paramv);

/**
 * Open an HSE KVDB for use by the application
 *
 * The KVDB must already exist and the client must have permission to use it. This
 * function is not thread safe.
 *
 * @param kvdb_home: KVDB home directory, NULL means current working directory
 * @param paramc: Number of configuration parameters in \p paramv
 * @param paramv: List of parameters in key=value format
 * @param kvdb: [out] Handle to access the opened KVDB
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_open(
    const char *       kvdb_home,
    size_t             paramc,
    const char *const *paramv,
    struct hse_kvdb ** kvdb);

/**
 * Close an open HSE KVDB
 *
 * No client thread may enter the HSE KVDB API with the referenced KVDB after this
 * function starts. This function is not thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_close(struct hse_kvdb *kvdb);

/**
 * Get the names of the KVSs within the given KVDB
 *
 * Key-value stores (KVSs) are opened by name. This function allocates a vector of
 * allocated strings, each containing the name of a KVS. The memory must be freed via
 * hse_kvdb_free_names(). This function is thread safe.
 *
 * Example Usage:
 *
 *     int     namec, i, rc;
 *     char  **namev;
 *
 *     rc = hse_kvdb_get_names(kvdb, &namec, &namev);
 *     if (!rc) {
 *         for (i = 0; i < namec; i++)
 *             printf("%s\n", namev[i]);
 *     }
 *     hse_kvdb_free_names(namev);
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param[out] count: Number of KVSs in the KVDB.
 * @param[out] kvs_list: Vector of KVSs. Allocated by the function
 * @return The function's error status
 *
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_get_names(struct hse_kvdb *kvdb, unsigned int *count, char ***kvs_list);

/**
 * Free the names collection obtained through hse_kvdb_get_names()
 *
 * This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param kvs_list: Vector of KVS names that hse_kvdb_get_names() output
 */
void
hse_kvdb_free_names(struct hse_kvdb *kvdb, char **kvs_list);

/**
 * Create a new KVS within the referenced KVDB
 *
 * If the KVS will store multi-segment keys then the parameter "pfx_len" should be set
 * to the desired key prefix length. Otherwise the param should be set to 0 (the default).
 * An error will result if there is already a KVS with the given name. This function is not
 * thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param kvs_name: KVS name
 * @param paramc: Number of configuration parameters in \p paramv
 * @param paramv: List of parameters in key=value format
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_kvs_create(
    struct hse_kvdb *  kvdb,
    const char *       kvs_name,
    size_t             paramc,
    const char *const *paramv);

/**
 * Remove a KVS from the referenced KVDB
 *
 * It is an error to call this function on a KVS that is open. This function is not
 * thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param kvs_name: KVS name
 * @return The function's error status
 */
hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *kvdb, const char *kvs_name);

/**
 * Open a KVS in a KVDB
 *
 * This function is not thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param kvs_name: KVS name
 * @param paramc: Number of configuration parameters in \p paramv
 * @param paramv: List of parameters in key=value format
 * @param[out] kvs_out: Handle to access the opened KVS
 * @return The function's error status
 */
hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *  handle,
    const char *       kvs_name,
    const size_t       paramc,
    const char *const *paramv,
    struct hse_kvs **  kvs_out);

/**
 * Close an open KVS
 *
 * No client thread may enter the HSE KVDB API with the referenced KVS after this
 * function starts. This function is not thread safe.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 * @return The function's error status
 */
hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *kvs);

/**@}*/

/** @name Create / Read / Update / Delete (CRUD) Functions
 *        =====================================================
 * @{
 */

/* Flags for put operation */

/* Operation will not be throttled */
#define HSE_FLAG_PUT_PRIORITY (1 << 0)

/**
 * Put a KV pair into KVS
 *
 * If the key already exists in the KVS then the value is effectively overwritten. The
 * key length must be in the range [1, HSE_KVS_KLEN_MAX] while the value length must be
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
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context
 * @param key: Key to put into kvs
 * @param key_len: Length of key
 * @param val: Value associated with key
 * @param val_len: Length of value
 * @return The function's error status
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

/**
 * Retrieve the value for a given key from KVS
 *
 * If the key exists in the KVS then the referent of "found" is set to true. If the
 * caller's value buffer is large enough then the data will be returned. Regardless, the
 * actual length of the value is placed in "val_len". See the section on transactions for
 * information on how gets within transactions are handled. This function is thread
 * safe.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context
 * @param key: Key to get from kvs
 * @param key_len: Length of key
 * @param[out] found: Whether or not key was found
 * @param[out] buf: Buffer into which the value associated with key will be copied
 * @param buf_len: Length of buffer
 * @param[out] val_len: [out] Actual length of value if key was found
 * @return The function's error status
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

/**
 * Delete the key and its associated value from KVS
 *
 * It is not an error if the key does not exist within the KVS. See the section on
 * transactions for information on how deletes within transactions are handled. This
 * function is thread safe.
 *
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context (optional)
 * @param key: Key to be deleted from kvs
 * @param key_len: Length of key
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         key,
    size_t               key_len);

/**
 * Delete all KV pairs matching the key prefix from a KVS storing multi-segment keys
 *
 * This interface is used to delete an entire range of multi-segment keys. To do this
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
 * @param kvs: KVS handle from hse_kvdb_kvs_open()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context (optional)
 * @param filt: Filter for keys to delete
 * @param filt_len: Filter length
 * @param[out] kvs_pfx_len: If specified, this will be set to the KVS's prefix length
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    const void *         filt,
    size_t               filt_len,
    size_t *             kvs_pfx_len);

/**@}*/

/** @name Transaction Functions
 *        =====================================================
 * @{
 */

/*
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
 * until it is committed. All such mutations become visible atomically.
 */

enum hse_kvdb_txn_state {
    HSE_KVDB_TXN_INVALID = 0,
    HSE_KVDB_TXN_ACTIVE = 1,
    HSE_KVDB_TXN_COMMITTED = 2,
    HSE_KVDB_TXN_ABORTED = 3,
};

/**
 * Allocate transaction object
 *
 * This object can and should be re-used many times to avoid the overhead of
 * allocation. This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @return The allocated transaction structure
 */
/* MTF_MOCK */
struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *kvdb);

/**
 * Free transaction object
 *
 * If the transaction handle refers to an ACTIVE transaction, the transaction is aborted
 * prior to being freed. This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param txn: KVDB transaction handle
 */
/* MTF_MOCK */
void
hse_kvdb_txn_free(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * Initiate transaction
 *
 * The call fails if the transaction handle refers to an ACTIVE transaction. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc()
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_begin(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * Commit all the mutations of the referenced transaction
 *
 * The call fails if the referenced transaction is not in the ACTIVE state. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc()
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * Abort/rollback transaction
 *
 * The call fails if the referenced transaction is not in the ACTIVE state. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc()
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * Retrieve the state of the referenced transaction
 *
 * This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param txn: KVDB transaction handle from hse_kvdb_txn_alloc()
 * @return The transaction's state
 */
/* MTF_MOCK */
enum hse_kvdb_txn_state
hse_kvdb_txn_get_state(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**@}*/

/** @name Cursor Functions
 *        =====================================================
 * @{
 */

/*
 * See the concept and best practices sections on the HSE Wiki at
 * https://github.com/hse-project/hse/wiki
 */

/* Flags for cursor usage */

/* Move the cursor in reverse */
#define HSE_FLAG_CURSOR_REVERSE (1 << 0)
/* Bind the cursor to a transaction */
#define HSE_FLAG_CURSOR_BIND_TXN (1 << 1)
/* Bound cursor's view is static */
#define HSE_FLAG_CURSOR_STATIC_VIEW (1 << 2)

/**
 * Creates a cursor used to iterate over a KVS
 *
 * When cursors are created they are by default forward iterating. If the caller of
 * hse_kvs_cursor_create() passes a flags parameter with the bit flag
 * HSE_KVDB_KOP_FLAG_REVERSE set, then a backwards (reverse sort order) iterating cursor
 * is created. A cursor's direction is determined when it is created and is immutable.
 *
 * Cursors are of one of three types: (1) free, (2) transaction snapshot, and (3)
 * transaction bound. A cursor of type (1) is based on an ephemeral snapshot view of the
 * KVS at the time it is created. New data is not visible to the cursor until
 * hse_kvs_cursor_update() is called on it. A cursor of type (2) takes on the
 * transaction's ephemeral snapshot but cannot see any of the mutations made by its
 * associated transaction. A cursor of type (3) is like type (2) but it always can see
 * the mutations made by the transaction. Calling hse_kvs_cursor_update() on a cursor of
 * types (2) and (3) without changing the transaction or flags parameters is a no-op. This
 * function is thread safe.
 *
 * The flags and transactions parameters shape the type and behavior of the cursor created. The
 * flag fields within kop_flags are independent.
 *
 *   - To create a cursor of type (1):
 *       - Pass a NULL as txn
 *
 *   - To create a cursor of type (2):
 *       - Pass a non-NULL txn
 *
 *   - To create a cursor of type (3):
 *       - Pass a non-NULL txn and a flags value with position HSE_FLAG_CURSOR_BIND_TXN set
 *
 * The primary utility of the prefix filter mechanism is to maximize the efficiency of
 * cursor iteration on a KVS with multi-segment keys. For that use case, the caller
 * should supply a filter whose length is greater than or equal to the KVS key prefix
 * length. The caller can also provide a filter that is shorter than the key prefix
 * length or can perform this operation on a KVS whose key prefix length is zero. In all
 * cases, the cursor will be restricted to keys matching the given prefix filter.
 *
 * When a transaction associated with a cursor of type (3) commits or aborts, the state
 * of the cursor becomes unbound, i.e., it becomes of type (1). What can be seen through
 * the cursor depends on whether it was created with the HSE_FLAG_CURSOR_STATIC_VIEW
 * flag set.
 *
 * If it was set, then the cursor retains the snapshot view of the transaction (for both
 * commit and abort). If it was not set then the view of the cursor is that of the
 * database at the time of the commit or abort. In the commit case, the cursor can see
 * the mutations of the transaction, if any. Note that this will make any other
 * mutations that occurred during the lifespan of the transaction visible as well.
 *
 * @param kvs: KVS to iterate over, handle from hse_kvdb_kvs_open()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context (optional)
 * @param filt: Iteration limited to keys matching this prefix filter (optional)
 * @param filt_len: Length of filter (optional)
 * @param[out] cursor: Cursor handle
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *        kvs,
    unsigned int            flags,
    struct hse_kvdb_txn *   txn,
    const void *            filt,
    size_t                  filt_len,
    struct hse_kvs_cursor **cursor);

/**
 * Update a plain cursor or modify any cursor
 *
 * This operation serves to either move the snapshot view forward for a type (1) cursor,
 * or to transition between being a type (1), type (2), and type (3) cursor.  That
 * includes toggling the state of the HSE_FLAG_CURSOR_STATIC_VIEW flag.  For example,
 * to "un-bind" a cursor from a transaction the caller may either NULL out the kop_txn
 * field or clear the HSE_FLAG_CURSOR_BIND_TXN flag. This function is thread safe
 * across disparate cursors.
 *
 * The flags and txn parameters must be unchanged and set to their original values
 * (as set at hse_kvs_cursor_create()).
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create()
 * @param flags: Flags for operation specialization
 * @param txn: Transaction context (optional)
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_update(struct hse_kvs_cursor *cursor, unsigned int flags, struct hse_kvdb_txn *txn);

/**
 * Move the cursor to point at the key/value pair at or closest to "key"
 *
 * The next hse_kvs_cursor_read() will start at this point. Both "found" and "found_len"
 * must be non-NULL for that functionality to work. This function is thread safe across
 * disparate cursors.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create()
 * @param flags: Flags for operation specialization
 * @param key: Key to find
 * @param key_len: Length of key
 * @param found: If non-NULL, referent point to next key in sequence (optional)
 * @param found_len: If "found" is non-NULL, referent is length of "found" key
 * @return The function's error status
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

/**
 * Move the cursor to the closest match to key, gated by the given filter
 *
 * Keys read from this cursor will belong to the closed interval defined by the given
 * filter: ["filt_min", "filt_max"]. For KVSs storing multi-segment keys, performance
 * will be enhanced when "filt_min_len" and "filt_max_len" are greater than or equal to
 * the KVS key prefix length.  Both "found" and "found_len" must be non-NULL for that
 * functionality to work. This function is thread safe across disparate cursors.
 *
 * Note: this is only supported for forward cursors.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create()
 * @param flags: Flags for operation specialization
 * @param filt_min: Filter minimum
 * @param filt_min_len: Length of filter minimum
 * @param filt_max: Filter maximum
 * @param filt_max_len: Length of filter maximum
 * @param[out] found: If non-NULL, referent points to next key in sequence (optional)
 * @param[out] found_len: If non-NULL, referent is length of "found" key (optional)
 * @return The function's error status
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

/**
 * Iteratively access the elements pointed to by the cursor
 *
 * Read a KV pair from the cursor, advancing the cursor past its current location. If
 * the cursor is at EOF, attempts to read from it will not change the state of the
 * cursor. This function is thread safe across disparate cursors.
 *
 * @param cursor:  Cursor handle from hse_kvs_cursor_create()
 * @param flags: Flags for operation specialization=
 * @param[out] key: Next key in sequence
 * @param[out] key_len: Length of key
 * @param[out] val: Next value in sequence
 * @param[out] val_len: Length of value
 * @param[out] eof: If true, no more key/value pairs in sequence
 * @return The function's error status
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

/**
 * Destroy cursor
 *
 * This function is thread safe.
 *
 * @param cursor: Cursor handle from hse_kvs_cursor_create()
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

/**@}*/

/** @name Data State Management Functions
 *        =====================================================
 * @{
 */

#define HSE_FLAG_SYNC_ASYNC (1 << 0)/* make the sync operation asynchronous */

/**
 * Sync data in all of the referenced KVDB's KVSs to stable media and return
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_sync(struct hse_kvdb *kvdb, unsigned int flags);

/* Flags for hse_kvdb_compact() */
#define HSE_KVDB_COMP_FLAG_CANCEL   0x01
#define HSE_KVDB_COMP_FLAG_SAMP_LWM 0x02

/**
 * Request a data compaction operation
 *
 * In managing the data within an HSE KVDB, there are maintenance activities that occur
 * as background processing. The application may be aware that it is advantageous to do
 * enough maintenance now for the database to be as compact as it ever would be in
 * normal operation. To achieve this, the client calls this function in the following
 * fashion:
 *
 *     hse_kvdb_compact(<kvdb handle>, HSE_KVDB_COMP_FLAG_SAMP_LWM);
 *
 * To cancel an ongoing compaction request for a KVDB:
 *
 *     hse_kvdb_compact(<kvdb handle>, HSE_KVDB_COMP_FLAG_CANCEL);
 *
 * See the function hse_kvdb_compact_status_get(). This function is thread safe.
 *
 * @param kvdb:  KVDB handle from hse_kvdb_open()
 * @param flags: Compaction flags
 * @return The function's error status
 */
hse_err_t
hse_kvdb_compact(struct hse_kvdb *kvdb, int flags);

/**
 * struct hse_kvdb_compact_status - status of a compaction request
 */
struct hse_kvdb_compact_status {
    unsigned int kvcs_samp_lwm;  /**< space amp low water mark (%) */
    unsigned int kvcs_samp_hwm;  /**< space amp high water mark (%) */
    unsigned int kvcs_samp_curr; /**< current space amp (%) */
    unsigned int kvcs_active;    /**< is an externally requested compaction underway */
    unsigned int kvcs_canceled;  /**< was an externally requested compaction canceled */
};

/**
 * Get status of an ongoing compaction activity
 *
 * The caller can examine the fields of the hse_kvdb_compact_status struct to determine
 * the current state of maintenance compaction. This function is thread safe.
 *
 * @param kvdb:   KVDB handle from hse_kvdb_open()
 * @param status: [out] Status of compaction request
 * @return The function's error status
 */
hse_err_t
hse_kvdb_compact_status_get(struct hse_kvdb *kvdb, struct hse_kvdb_compact_status *status);

/**
 * struct hse_kvdb_storage_info - storage info for a kvdb
 */
struct hse_kvdb_storage_info {
    uint64_t total_bytes;     /**< total space in the file-system containing this kvdb */
    uint64_t available_bytes; /**< available space in the file-system containing this kvdb */
    uint64_t allocated_bytes; /**< allocated storage space for a kvdb */
    uint64_t used_bytes;      /**< used storage space for a kvdb */
};

/**
 * Get storage config and stats
 *
 * Obtain the storage paths, allocated and used space for a specified kvdb.
 * This function is thread safe.
 *
 * @param kvdb: KVDB handle from hse_kvdb_open()
 * @param info: [out] KVDB storage config and stats
 * @return The function's error status
 */
hse_err_t
hse_kvdb_storage_info_get(struct hse_kvdb *kvdb, struct hse_kvdb_storage_info *info);

/**@}*/

#pragma GCC visibility pop

#if HSE_MOCKING
#include "hse_ut.h"
#endif /* HSE_MOCKING */

#ifdef __cplusplus
}
#endif

#endif
