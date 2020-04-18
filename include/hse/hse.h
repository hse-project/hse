/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
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
 */

#include <hse/hse_limits.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


/*
 * Type Declarations / Shared Structures / Macros
 * =====================================================
 */

/** @name Type Declarations / Shared Structures / Macros
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
 * @typedef hse_params
 * @brief Opaque structure defining a collection of parameters governing KVDB
 *        and KVS settings
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
struct hse_params;
struct hse_kvdb;
struct hse_kvs;
struct hse_kvs_cursor;
struct hse_kvdb_txn;

/**
 * @typedef hse_kvdb_opspec
 * @brief Structure and flag definitions that allow customization of entry
 *        point behavior.
 *
 * This structure may evolve as the HSE API grows. Failure to use the macro
 * HSE_KVDB_OPSPEC_INIT() to initialize an hse_kvdb_opspec will cause calls using it to
 * fail. Once init'd the programmer can freely manipulate the kop_flags and kop_txn
 * fields. Modifying kop_opaque or relying in any way on its structure will result in
 * undefined behavior.
 */

struct hse_kvdb_opspec {
    unsigned int         kop_opaque; /**< opaque data */
    unsigned int         kop_flags;  /**< opspec flags */
    struct hse_kvdb_txn *kop_txn;    /**< transaction context */
};

#define HSE_KVDB_OPSPEC_INIT(os)       \
    do {                               \
        (os)->kop_opaque = 0xb0de0001; \
        (os)->kop_flags = 0x00000000;  \
        (os)->kop_txn = NULL;          \
    } while (0)

#define HSE_KVDB_KOP_FLAG_REVERSE 0x01     /**< reverse cursor */
#define HSE_KVDB_KOP_FLAG_BIND_TXN 0x02    /**< cursor bound to transaction */
#define HSE_KVDB_KOP_FLAG_STATIC_VIEW 0x04 /**< bound cursor's view is static */
#define HSE_KVDB_KOP_FLAG_PRIORITY 0x08    /**< op won't be throttled @see, hse_kvs_put */

/**@}*/


/*
 * Utility Routines
 * =====================================================
 */

/** @name Utility Routines
 * @{
 */

/**
 * Initialize the HSE KVDB subsystem
 *
 * This function initializes a range of different internal HSE structures. It must be
 * called before any other HSE functions are used. It is not thread safe and is
 * idempotent.
 */
hse_err_t
hse_kvdb_init(void);

/**
 * Shutdown the HSE KVDB subsystem
 *
 * This function cleanly finalizes a range of different internal HSE structures. It
 * should be called prior to application exit and is not thread safe. After it is
 * invoked (and even before it returns), calling any other HSE functions will result in
 * undefined behavior. This function is not thread safe.
 */
void
hse_kvdb_fini(void);

/**
 * Returns a string representing the HSE KVDB libary version
 *
 * The version string starts with a numeric sequence (e.g., 1.7.0) and then, depending
 * on the type of build may have additional information appended. This function is
 * thread safe.
 */
const char *
hse_kvdb_version_string(void);

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


/*
 * Primary Lifecycle Functions
 * =====================================================
 */

/** @name Primary Lifecycle Functions
 * @{
 */

/**
 * Create a new KVDB instance within the named mpool
 *
 * The mpool must already exist and the client must have permission to use the
 * mpool. This function is not thread safe.
 *
 * @param mp_name: Mpool name
 * @param params:  Fixed configuration parameters
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_make(const char *mp_name, struct hse_params *params);

/**
 * Open an HSE KVDB for use by the application
 *
 * The KVDB must already exist and the client must have permission to use it. This
 * function is not thread safe.
 *
 * @param mp_name: Mpool name in which the KVDB exists
 * @param params:  Configuration-time parameters
 * @param kvdb:    [out] Handle to access the opened KVDB
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_open(const char *mp_name, struct hse_params *params, struct hse_kvdb **kvdb);

/**
 * Close an open HSE KVDB
 *
 * No client thread may enter the HSE KVDB API with the referenced KVDB after this
 * function starts. This function is not thread safe.
 *
 * @param kvdb: KVDB handle
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_close(struct hse_kvdb *kvdb);

/**
 * Get the names of the KVSs within the given KVDB
 *
 * Key-value stores (KVSs) are opened by name. This function allocates a vector of
 * allocated strings, each containing the name of a KVS. The memory must be free via
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
 * @param kvdb:     KVDB handle
 * @param count:    [out] Number of KVSs in the KVDB.
 * @param kvs_list: [out] Vector of KVSs. Allocated by the function
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
 * @param kvdb:     KVDB handle
 * @param kvs_list: Vector of KVS names that hse_kvdb_get_names() output
 */
void
hse_kvdb_free_names(struct hse_kvdb *kvdb, char **kvs_list);

/**
 * Create a new KVS within the referenced KVDB
 *
 * An error will result if there is already a KVS with the given name. This function is
 * not thread safe.
 *
 * @param kvdb:     KVDB handle
 * @param kvs_name: KVS name
 * @param params:   Fixed configuration parameters
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_kvs_make(struct hse_kvdb *kvdb, const char *kvs_name, struct hse_params *params);

/**
 * Remove a KVS from the referenced KVDB
 *
 * It is an error to call this function on a KVS that is open. This function is not
 * thread safe.
 *
 * @param kvdb:     KVDB handle
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
 * @param kvdb:     KVDB handle
 * @param kvs_name: KVS name
 * @param params:   Parameters that affect how the KVS will function
 * @param kvs_out:  [out] handle to access the opened KVS
 * @return The function's error status
 */
hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *  kvdb,
    const char *       kvs_name,
    struct hse_params *params,
    struct hse_kvs **  kvs_out);

/**
 * Close an open KVS
 *
 * No client thread may enter the HSE KVDB API with the referenced KVS after this
 * function starts. This function is not thread safe.
 *
 * @param kvs: KVS handle
 * @return The function's error status
 */
hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *kvs);

/**@}*/


/*
 * Create / Read / Update / Delete (CRUD) Functions
 * =====================================================
 */

/** @name Create / Read / Update / Delete (CRUD) Functions
 * @{
 */

/**
 * Put a key/value pair into the KVS identified by handle
 *
 * If the key already exists in the KVS then the value is effectively overwritten. The
 * key length must be in the range [1, HSE_KVS_KLEN_MAX] while the value length must be
 * in the range [0, HSE_KVS_VLEN_MAX]. See the section on transactions for information
 * on how puts within transactions are handled. This function is thread safe.
 *
 * @param kvs:     KVS handle
 * @param opspec:  Specification for put operation
 * @param key:     Key to put into kvs
 * @param key_len: Length of key
 * @param val:     Value associated with key
 * @param val_len: Length of value
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_put(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    const void *            val,
    size_t                  val_len);

/**
 * Retrieve the value for a given key
 *
 * If the key exists in the KVS then the referent of "found" is set to true. If the
 * caller's value buffer is large enough then the data will be returned. Regardless, the
 * actual length of the value is plced in "val_len". See the section on transactions for
 * information on how gets within transactions are handled. This function is thread
 * safe.
 *
 * @param kvs:     KVS handle
 * @param opspec:  Specification for get operation
 * @param key:     Key to get from kvs
 * @param key_len: Length of key
 * @param found:   [out] Whether or not key was found
 * @param buf:     Buffer into which the value associated with key will be copied
 * @param buf_len: Length of buffer
 * @param val_len: [out] Actual length of value if key was found
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_get(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    bool *                  found,
    void *                  buf,
    size_t                  buf_len,
    size_t *                val_len);

/**
 * Delete the key and its associated value from the KVS
 *
 * It is not an error if the key does not exist within the KVS. See the section on
 * transactions for information on how deletes within transactions are handled. This
 * function is thread safe.
 *
 * @param kvs:     KVS handle
 * @param opspec:  Specification for delete operation
 * @param key:     Key to be deleted from kvs
 * @param key_len: Length of key
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_delete(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len);

/**
 * Delete all key/value pairs with the given prefix
 *
 * It is not an error if no keys exist with the given prefix. This function can only be
 * used if the KVS was created using a non-zero prefix length and the prefix given to
 * this function has that same length. If there is a prefix scan in progress, then that
 * scan can fail if hse_kvs_prefix_delete() is called with a prefix matching the scan.
 * See the section on transactions for information on how deletes within transactions
 * are handled. This function is thread safe.
 *
 * @param kvs:         KVS handle
 * @param opspec:      KVDB op struct
 * @param pfx_key:     Prefix key to delete
 * @param pfx_len:     Prefix key length
 * @param kvs_pfx_len: [out] If specified, this will be set to the KVS's prefix
 *                     length
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            pfx_key,
    size_t                  pfx_len,
    size_t *                kvs_pfx_len);

/**@}*/


/*
 * Transaction Functions
 * =====================================================
 */

/** @name Transaction Functions
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
 * Allocate a transaction object
 *
 * This object can and should be re-used many times to avoid the overhead of
 * allocation. This function is thread safe.
 *
 * @param kvdb: KVDB handle
 * @return The allocated transaction structure
 */
/* MTF_MOCK */
struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *kvdb);

/**
 * Free a transaction
 *
 * If the transaction handle refers to an ACTIVE transaction, the transaction is aborted
 * prior to being freed. This function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle
 * @param txn:  KVDB transaction handle
 */
/* MTF_MOCK */
void
hse_kvdb_txn_free(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * Initiate a transaction.
 *
 * The call fails if the transaction handle refers to an ACTIVE transaction. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle
 * @param txn:  KVDB transaction handle
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
 * @param kvdb: KVDB handle
 * @param txn:  KVDB transaction handle
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * Abort/rollback the transaction
 *
 * The call fails if the referenced transaction is not in the ACTIVE state. This
 * function is thread safe with different transactions.
 *
 * @param kvdb: KVDB handle
 * @param txn:  KVDB transaction handle
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
 * @param kvdb: KVDB handle
 * @param txn:  KVDB transaction handle
 * @return The transaction's state
 */
/* MTF_MOCK */
enum hse_kvdb_txn_state
hse_kvdb_txn_get_state(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**@}*/


/*
 * Cursor Functions
 * =====================================================
 */

/** @name Cursor Functions
 * @{
 */

/*
 * Note regarding the use of cursors:
 *
 * The data structures used to implement HSE are better suited for single-key operations
 * (put/get/delete) than for cursor-based operations. In many other storage engines,
 * there is not such a disparity. If your application can accomplish what it needs with
 * single-key operations, with or without transactions, then that is recommended. Using
 * a mix of single-key operations as well as cursors where the latter are required is
 * strongly encouraged.
 *
 * A cursor create, seek, read, destroy sequence will be much slower than a single
 * hse_kvs_get() call.
 */

/**
 * Creates a cursor used to iterate over a KVS
 *
 * When cursors are created they are by default forward iterating. If the caller of
 * hse_kvs_cursor_create() passes a reference to an initialized opspec with bit flag
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
 * types (2) and (3) without changing the hse_kvdb_opspec fields is a no-op. This
 * function is thread safe.
 *
 * The hse_kvdb_opspec referent shapes the type and behavior of the cursor created. The
 * flag fields within kop_flags are independent. Passing a NULL for the opspec is the
 * same as passing an initialized but otherwise unmodified opspec.
 *
 *   - To create a cursor of type (1):
 *       - Pass either a NULL for opspec, or
 *       - Pass an initialized opspec with kop_txn == NULL
 *
 *   - To create a cursor of type (2):
 *       - Pass an initialized opspec with kop_txn == <target txn>
 *
 *   - To create a cursor of type (3):
 *       - Pass an initialized opspec with kop_txn == <target txn> and
 *         a kop_flags value with position HSE_KVDB_KOP_FLAG_BIND_TXN set
 *
 * If the caller provides a prefix, which need not match the prefix segment that the KVS
 * was created with, then the cursor will be restricted to keys with the given prefix.
 *
 * When a transaction associated with a cursor of type (3) aborts, the cursor remains
 * valid and retains the snapshot view of the transaction. When a transaction associated
 * with a cursor of type (3) commits, the behavior depends on the state of the
 * HSE_KVDB_KOP_FLAG_STATIC_VIEW bit position. If it is set, then the cursor retains the
 * snapshot view of the transaction. If it is not set then the cursor view is shifted
 * forward in time to be able to see the mutations of the transaction. Note that this
 * may make other mutations visible to the cursor as well.
 *
 * @param kvs:     KVS to iterate over
 * @param opspec:  Optional flags, optional txn
 * @param pfx:     Optional: scans limited to this prefix
 * @param pfx_len: Optional: length of prefix
 * @param cursor:  [out] Cursor handle
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            pfx,
    size_t                  pfx_len,
    struct hse_kvs_cursor **cursor);

/**
 * Update a plain cursor or modify any cursor
 *
 * This operation serves to either move the snapshot view forward for a type (1) cursor,
 * or to transition between being a type (1), type (2), and type (3) cursor.  That
 * includes toggling the state of the HSE_KVDB_KOP_FLAG_STATIC_VIEW flag.  For example,
 * to "un-bind" a cursor to a transaction the caller may either NULL out the kop_txn
 * field or clear the HSE_KVDB_KOP_FLAG_BIND_TXN flag. This function is thread safe
 * across disparate cursors.
 *
 * @param cursor: Cursor from hse_kvs_cursor_create
 * @param opspec: Optional flags, optional txn
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_update(struct hse_kvs_cursor *cursor, struct hse_kvdb_opspec *opspec);

/**
 * Move the cursor to point at the key/value pair at or closest to "key"
 *
 * The next hse_kvs_cursor_read() will start at this point. Both "found" and "found_len"
 * must be non-NULL for that functionality to work. This function is thread safe across
 * disparate cursors.
 *
 * @param cursor:    Cursor from hse_kvs_cursor_create
 * @param opspec:    Ignored; must be zero
 * @param key:       Key to find
 * @param key_len:   Length of key
 * @param found:     Optional: If non-NULL, referent point to next key in sequence
 * @param found_len: Optional: If "found" is non-NULL: referent is length of "found" key
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_seek(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    const void **           found,
    size_t *                found_len);

/**
 * Move the cursor to the closest match to key, gated by the given limit
 *
 * Keys read from this cursor will belong to the closed interval: [key, limit]. The next
 * hse_kvs_cursor_read() will resume at this point. This call is the same as
 * hse_kvs_cursor_seek() except that the caller is telling the system that this cursor
 * need not return any key-value pairs beyond "limit". Both "found" and "found_len" must
 * be non-NULL for that functionality to work. This function is thread safe across
 * disparate cursors.
 *
 * Note that this is supported only for forward cursors.
 *
 * @param cursor:    Cursor from hse_kvs_cursor_create
 * @param opspec:    Unused
 * @param key:       Key to find
 * @param key_len:   Length of key
 * @param limit:     Limit for access
 * @param limit_len: Length of limit
 * @param found:     Optional: If non-NULL, referent point to next key in sequence
 * @param found_len: Optional: If "found" is non-NULL: referent is length of "found" key
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_seek_range(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    const void *            limit,
    size_t                  limit_len,
    const void **           found,
    size_t *                found_len);

/**
 * hse_kvs_cursor_read() - iteratively access the elements pointed to by the cursor
 *
 * Read a key/value pair from the cursor, advancing the cursor past its current
 * location. If the cursor is at EOF, attempts to read from it will not change the state
 * of the cursor. This function is thread safe across disparate cursors.
 *
 * @param cursor:  Cursor from hse_kvs_cursor_create
 * @param opspec:  Ignored; may be zero
 * @param key:     [out] Next key in sequence
 * @param key_len: [out] Length of key
 * @param val:     [out] Next Value in sequence
 * @param val_len: [out] Length of value
 * @param eof:     [out] If true, no more key/value pairs in sequence
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_read(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *opspec,
    const void **           key,
    size_t *                key_len,
    const void **           val,
    size_t *                val_len,
    bool *                  eof);

/**
 * hse_kvs_cursor_destroy() - destroys the cursor handle
 *
 * This function is thread safe.
 *
 * @param cursor: Cursor from hse_kvs_cursor_create
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

/**@}*/


/*
 * Data State Management Functions
 * =====================================================
 */

/** @name Data State Management Functions
 * @{
 */

/**
 * Flush data in all of the referenced KVDB's KVSs to stable media and return
 *
 * @param kvdb: KVDB handle
 * @return The function's error status
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_sync(struct hse_kvdb *kvdb);

/**
 * Initiate data flush in all of the referenced KVDB's KVSs
 *
 * @param kvdb: KVDB handle
 * @return The function's error status
 */
hse_err_t
hse_kvdb_flush(struct hse_kvdb *kvdb);

/* Flags for hse_kvdb_compact() */
#define HSE_KVDB_COMP_FLAG_CANCEL 0x01
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
 * See the function hse_kvdb_compact_status(). This function is thread safe.
 *
 * @param handle: Initiate/cancel compaction for this KVDB
 * @param flags:  Compaction flags
 * @return The function's error status
 */
hse_err_t
hse_kvdb_compact(struct hse_kvdb *handle, int flags);

/**
 * struct hse_kvdb_compact_status - status of a compaction request
 */
struct hse_kvdb_compact_status {
    unsigned int kvcs_samp_lwm;  /**< space amp low water mark (%) */
    unsigned int kvcs_samp_hwm;  /**< space amp high water mark (%) */
    unsigned int kvcs_samp_curr; /**< current space amp (%) */
    unsigned int kvcs_active;    /**< is an externally requested compaction underway */
};

/**
 * Get status of an ongoing compaction activity
 *
 * The caller can examine the fields of the hse_kvdb_compact_status struct to determine
 * the current state of maintenance compaction. This function is thread safe.
 *
 * @param handle: Get compaction status of this KVDB
 * @param status: [out] Status of compaction request
 * @return The function's error status
 */
hse_err_t
hse_kvdb_compact_status(struct hse_kvdb *handle, struct hse_kvdb_compact_status *status);

/**@}*/


/*
 * Configuration Parameter Functions
 * =====================================================
 */

/** @name Create and Runtime Parameter Functions
 * @{
 */

/**
 * Create a params object
 *
 * This function allocates an empty params object. This object can then be populated
 * through hse_params_from_file(), hse_params_from_string(), or via hse_params_set().
 * Usage of a given params object is not thread safe.
 *
 * @param params: [out] Configuration parameters
 * @return The function's error status
 */
hse_err_t
hse_params_create(struct hse_params **params);

/**
 * Destroy params object
 *
 * This function frees a params object, whether empty or populated. After it is
 * destroyed it may no longer be used.
 *
 * @param params: Configuration parameters
 */
void
hse_params_destroy(struct hse_params *params);

/**
 * Parse params from a file
 *
 * This function takes a filename and parses it, populating the supplied params
 * object. If the file is not a valid params specification, the parsing will
 * fail. Client applications can use the experimental function hse_params_err_exp() to
 * get more information as to what problem occurred in processing the file. This
 * function is not thread safe.
 *
 * @param params: Configuration parameters
 * @param path:   Absolute path to config file
 * @return The function's error status
 */
hse_err_t
hse_params_from_file(struct hse_params *params, const char *path);

/**
 * Parse params from a string
 *
 * This function takes a string and parses it, populating the supplied params object. If
 * the string is not a valid params specification, the parsing will fail. Client
 * applications can use the experimental function hse_params_err_exp() to get more
 * information as to what problem occurred in processing the string. This function is
 * not thread safe.
 *
 * @param params: Referenced params object
 * @param input:  Buffer with configuration
 * @return The function's error status
 */
hse_err_t
hse_params_from_string(struct hse_params *params, const char *input);

/**
 * Set configuration parameter
 *
 * Set the parameter setting given by "key" to "value". If the "key" or "value" is
 * invalid then the call will fail. Client applications can use the experimental
 * function hse_params_err_exp() to get more information about what problem occurred.
 *
 * The following syntax is supported for keys:
 *
 *   kvdb.<param>           # param is set for the KVDB
 *   kvs.<param>            # param is set for all KVSs in the KVDB
 *   kvs.<kvs_name>.<param> # param is set for the named KVS
 *
 * This function is not thread safe.
 *
 * @param params: Referenced params object
 * @param key:    Target key
 * @param val:    Target value
 * @return The function's error status
 */
hse_err_t
hse_params_set(struct hse_params *params, const char *key, const char *val);

/**
 * Get configuration parameter
 *
 * Obtain the value the parameter denoted by "key" is set to in the params object. If
 * the key is valid, then at most "buf_len"-1 bytes of the parameter setting will copied
 * into "buf". If "param_len" is non-NULL, then on return the referent will contain the
 * length of the parameter value. This function is not thread safe.
 *
 * @param params:    Referenced params object
 * @param key:       Target key
 * @param buf:       Output buffer
 * @param buf_len:   Length of buffer
 * @param param_len: [out] If non-NULL this will be set to the actual parameter length + 1
 * @return The parameter's NULL-terminated string representation, possibly truncated
 */
char *
hse_params_get(
    struct hse_params *params,
    const char *       key,
    char *             buf,
    size_t             buf_len,
    size_t *           param_len);

/**@}*/

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "hse_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
