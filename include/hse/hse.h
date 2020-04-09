/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_API_H
#define HSE_KVDB_API_H

#include <hse/hse_limits.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* MTF_MOCK_DECL(hse) */

typedef uint64_t hse_err_t;

/* Opaque Types */

struct hse_params;
struct hse_kvdb;
struct hse_kvs;
struct hse_kvs_cursor;
struct hse_kvdb_txn;

/* Operation Specifier ("opspec")
 *
 * Structure and flag definitions that allow customization of entry point
 * behavior.
 */

/**
 * @kop_opaque:  opaque data - do not modify or rely on anything about this field
 * @kop_flags:   flags for operation
 * @kop_txn:     transaction structure
 */
struct hse_kvdb_opspec {
    unsigned int         kop_opaque;
    unsigned int         kop_flags;
    struct hse_kvdb_txn *kop_txn;
};

#define HSE_KVDB_OPSPEC_INIT(os)       \
    do {                               \
        (os)->kop_opaque = 0xb0de0001; \
        (os)->kop_flags = 0x0000;      \
        (os)->kop_txn = NULL;          \
    } while (0)

#define HSE_KVDB_KOP_FLAG_REVERSE 0x01
#define HSE_KVDB_KOP_FLAG_BIND_TXN 0x02
#define HSE_KVDB_KOP_FLAG_STATIC_VIEW 0x04
#define HSE_KVDB_KOP_FLAG_PRIORITY 0x08
#define HSE_KVDB_KOP_FLAG_CURSOR_RA 0x10

/* API Entry Points */

/**
 * hse_kvdb_init() - initialize the HSE KVDB subsystem
 */
hse_err_t
hse_kvdb_init(void);

/**
 * hse_kvdb_fini() - shutdown the HSE KVDB subsystem
 */
void
hse_kvdb_fini(void);

/**
 * hse_kvdb_version_string() - returns a string representing the HSE KVDB libary version
 */
const char *
hse_kvdb_version_string(void);

/**
 * hse_kvdb_make() - create a new KVDB instance within the named mpool
 * @mp_name:        mpool name
 * @params:         fixed configuration parameters
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_make(const char *mp_name, struct hse_params *params);

/**
 * hse_kvdb_open() - prepare an HSE KVDB target for subsequent use by the application
 * @mp_name:        mpool/kvdb name
 * @params:         fixed configuration parameters
 * @kvdb:           (output) handle to access the opened KVDB
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_open(const char *mp_name, struct hse_params *params, struct hse_kvdb **kvdb);

/**
 * hse_kvdb_close() - indicate that the KVDB will no longer be used
 * @kvdb: KVDB handle
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_close(struct hse_kvdb *kvdb);

/**
 * hse_kvdb_get_names() -
 * @kvdb:     KVDB handle
 * @count:    (output)number of KVSes in the KVDB.
 * @kvs_list: (output)vector of KVSes. Allocated by the function
 *
 * for example,
 *
 * int     namec, i, rc;
 * char  **namev;
 *
 * rc = hse_kvdb_get_names(kvdb, &namec, &namev);
 * if (!rc) {
 *     for (i = 0; i < namec; i++) {
 *         printf("%s\n", namev[i]);
 *     }
 *     hse_kvdb_free_names(namev);
 * }
 *
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_get_names(struct hse_kvdb *kvdb, unsigned int *count, char ***kvs_list);

/**
 * hse_kvdb_free_names() -
 * @kvdb:     KVDB handle
 * @kvs_list: vector of KVS names that hse_kvdb_get_names() output
 */
void
hse_kvdb_free_names(struct hse_kvdb *kvdb, char **kvs_list);

/**
 * hse_kvdb_kvs_count() - Get the number of KVSes in the KVDB
 * @kvdb:   KVDB handle
 * @count:  (output) number of KVSes
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_kvs_count(struct hse_kvdb *kvdb, unsigned int *count);

/**
 * hse_kvdb_kvs_make() - allow a new KVS to be created within a KVDB
 * @kvdb:        KVDB handle
 * @kvs_name:    KVS name
 * @params:      fixed configuration parameters
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_kvs_make(struct hse_kvdb *kvdb, const char *kvs_name, struct hse_params *params);

/**
 * hse_kvdb_kvs_drop() - drop a kvs from a kvdb
 * @kvdb:        KVDB handle
 * @kvs_name:    KVS name
 */
hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *handle, const char *kvs_name);

/**
 * hse_kvdb_kvs_open() - open a KVS in a KVDB
 * @kvdb:     KVDB handle
 * @kvs_name: KVS name
 * @params:   parameters that affect how the KVS will function
 * @kvs_out:  (output) handle to access the opened KVS
 */
hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *  kvdb,
    const char *       kvs_name,
    struct hse_params *params,
    struct hse_kvs **  kvs_out);

/**
 * hse_kvdb_kvs_close() - close KVS
 * @kvs:     KVS handle
 */
hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *kvs);

/**
 * hse_kvs_put() - insert a new key/value pair into the KVS identified by handle.
 * Any value already associated with the key is overwritten.
 *
 * @kvs:     KVS handle
 * @opspec:  specification for put operation
 * @key:     key to put into kvs
 * @key_len: length of @key
 * @val:     value associated with @key
 * @val_len: length of @val
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
 * hse_kvs_get() - Search for given key and if found,
 *
 *  1. the value is copied into the user supplied buffer. At most valbuf_sz
 *     bytes of the value are copied.
 *  2. *val_len is set to the value length.
 *  3. *found is set to true.
 *
 * @kvs:        KVS handle
 * @opspec:     specification for get operation
 * @key:        key to get from kvs
 * @key_len:    length of @key
 * @found:      (output) whether or not @key was found
 * @valbuf:     buffer into which the value associated with @key will be copied
 * @valbuf_sz:  size of @valbuf
 * @val_len:    (output) actual length of value if key was found. may exceed
 *              @valbuf_sz
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_get(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    bool *                  found,
    void *                  valbuf,
    size_t                  valbuf_sz,
    size_t *                val_len);

/**
 * hse_kvs_delete() - remove the supplied key and associated value from the KVS
 * identified by handle.
 *
 * @kvs:     KVS handle
 * @opspec:  specification for delete operation
 * @key:     key to be deleted from @kvs
 * @key_len: length of @key
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_delete(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len);

/**
 * hse_kvs_prefix_delete() - remove all key/value pairs with the given prefix
 * from the KVS identified by handle. If a prefix scan is in progress
 * for a matching prefix, the scan can fail after the hse_kvs_prefix_delete().
 * @kvs:        KVS handle
 * @opspec:     KVDB op struct
 * @prefix_key: prefix key to delete
 * @key_len:    prefix key length
 * @kvs_pfxlen: (output) if specified, this will be set to the kvs's prefix
 *              length
 *
 * This can only be used if the kvs was created using a non-zero pfxlen and the
 * prefix used in this call has that same length.
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            prefix_key,
    size_t                  key_len,
    size_t *                kvs_pfxlen);

/**
 * hse_kvdb_sync() - flush data in all of the KVSes to stable media.
 * @kvdb: KVDB handle
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_sync(struct hse_kvdb *kvdb);

/**
 * hse_kvdb_flush() - initiate data flush in all of the KVSes to stable media.
 * @kvdb: KVDB handle
 */
hse_err_t
hse_kvdb_flush(struct hse_kvdb *kvdb);

enum hse_kvdb_txn_state {
    HSE_KVDB_TXN_INVALID = 0,
    HSE_KVDB_TXN_ACTIVE = 1,
    HSE_KVDB_TXN_COMMITTED = 2,
    HSE_KVDB_TXN_ABORTED = 3,
};

/**
 * hse_kvdb_txn_alloc() - allocate a transaction, may be used any number of times
 * @kvdb: KVDB handle
 */
/* MTF_MOCK */
struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *kvdb);

/**
 * hse_kvdb_txn_free() - free a transaction
 * @kvdb: KVDB handle
 * @txn:  kvdb transaction handle
 */
/* MTF_MOCK */
void
hse_kvdb_txn_free(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * hse_kvdb_txn_begin() - initiate a transaction.
 * @kvdb: KVDB handle
 * @txn:  kvdb transaction handle
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_begin(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * hse_kvdb_txn_commit() - publish all mutations performed in the context of txn.
 * @kvdb: KVDB handle
 * @txn:  kvdb transaction handle
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * hse_kvdb_txn_abort() - abort all mutations performed in the context of txn,
 * such that they are not visible in any subsequent access.
 * @kvdb: KVDB handle
 * @txn:  kvdb transaction handle
 */
/* MTF_MOCK */
hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * hse_kvdb_txn_get_state() - retrieve the state of the transaction, one of
 * KVDB_TXN_ACTIVE, KVDB_TXN_COMMITTED, or KVDB_TXN_ABORTED.
 * @kvdb: KVDB handle
 * @txn:  kvdb transaction handle
 */
/* MTF_MOCK */
enum hse_kvdb_txn_state
hse_kvdb_txn_get_state(struct hse_kvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * hse_kvs_cursor_create() - creates a cursor used to iterate over a KVS
 * @kvs:     scan this kvs
 * @opspec:  optional scan direction, optional txn
 * @prefix:  optional: scans limited to this prefix
 * @pfxlen:  optional: length of prefix
 * @cursor:  the cursor handle; use by all other cursor calls
 *
 * Returns: sets cursor handle and returns 0 on success;
 * sets cursor handle to 0 and returns errno if error occurred
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            prefix,
    size_t                  pfxlen,
    struct hse_kvs_cursor **cursor);

/**
 * hse_kvs_cursor_update() - incorporate updates since cursor created.
 * @cursor:  the cursor from hse_kvs_cursor_create
 * @opspec:  optional; if set, its kop_txn field specifies transaction.
 *           Use the flag KVDB_KOP_FLAG_BIND_TXN to specify whether or not to
 *           bind cursor to the txn.
 *           To unbind a bound cursor, set this flag to zero.
 *
 * Note: Bound cursors can automatically see all mutations local to the txn.
 *
 * Returns: errno if error occurred
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_update(struct hse_kvs_cursor *cursor, struct hse_kvdb_opspec *opspec);

/**
 * hse_kvs_cursor_seek() - move the cursor to the closest match to @key.
 * @cursor:  the cursor from hse_kvs_cursor_create
 * @opspec:  ignored; must be zero
 * @key:     the key to find
 * @key_len: length of this key
 * @found:   optional: on return is set to a pointer to the next key in sequence
 * @flen:    required if @found: the length of this key
 *
 * The next hse_kvs_cursor_read() will resume at this point.
 *
 * Returns: errno if error occurred; not finding match is not an error
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_seek(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    const void **           found,
    size_t *                flen);

/**
 * hse_kvs_cursor_seek_range() - move the cursor to the closest match to @key,
 *                           gated by the given @limit. Keys read from this
 *                           cursor will belong to the closed interval:
 *                           [key, limit].
 *
 * @cursor:    the cursor from hse_kvs_cursor_create
 * @opspec:    ignored; must be zero
 * @key:       the key to find
 * @key_len:   length of this key
 * @limit:     the limit for access
 * @limit_len: length of this key
 * @found:     optional: on return is set to a pointer to the next key in
 *             sequence
 * @flen:      required if @found: the length of this key
 *
 * The next hse_kvs_cursor_read() will resume at this point. This call is the
 * same as hse_kvs_cursor_seek() except that the caller is telling the system
 * that this cursor need not return any key-value pairs beyond @limit.
 *
 * Note that this is supported only for forward cursors.
 *
 * Returns: errno if error occurred; not finding match is not an error
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_seek_range(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *os,
    const void *            key,
    size_t                  key_len,
    const void *            limit,
    size_t                  limit_len,
    const void **           found,
    size_t *                flen);

/**
 * hse_kvs_cursor_read() - iteratively access the elements pointed to by the cursor
 * @cursor:  the cursor from hse_kvs_cursor_create
 * @opspec:  ignored; may be zero
 * @key:     the next key in sequence
 * @key_len: length of this key
 * @val:     value for this key
 * @val_len: length of this value
 * @eof:     boolean: if true, no more keys in sequence
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
 * @cursor:  the cursor from hse_kvs_cursor_create
 */
/* MTF_MOCK */
hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

/* Flags for hse_kvdb_compact() */
#define HSE_KVDB_COMP_FLAG_CANCEL 0x01
#define HSE_KVDB_COMP_FLAG_SAMP_LWM 0x02

/**
 * hse_kvdb_compact() - Request a compaction operation
 * @handle: Initiate/cancel compaction for this KVDB
 * @os:     Opspec
 * @flags:  Compaction flags
 */
hse_err_t
hse_kvdb_compact(struct hse_kvdb *handle, int flags);

/**
 * struct hse_kvdb_compact_status - Check the status of a compation request
 * @kvcs_samp_lwm:  low watermark for space amp percentage
 * @kvcs_samp_hwm:  high watermark for space amp percentage
 * @kvcs_samp_curr: current space amp percentage
 * @kvcs_active:    whether there's an active compaction request
 */
struct hse_kvdb_compact_status {
    unsigned int kvcs_samp_lwm;
    unsigned int kvcs_samp_hwm;
    unsigned int kvcs_samp_curr;
    unsigned int kvcs_active;
};

/**
 * hse_kvdb_compact_status() - Get status of compaction request
 * @handle: Get compaction status of this KVDB
 * @os:     Opspec
 * @status: (out) status of compaction request
 */
hse_err_t
hse_kvdb_compact_status(struct hse_kvdb *handle, struct hse_kvdb_compact_status *status);

/**
 * hse_err_to_string() - transform an HSE error to a string representation
 * @err:   error value returned from an HSE API entry point
 * @buf:   buffer to hold the formatted string
 * @buf_sz: size of the buffer
 * @need_sz: size of the buffer
 */
char *
hse_err_to_string(hse_err_t err, char *buf, size_t buf_sz, size_t *need_sz);

/**
 * hse_err_to_errno() - return the equivalent errno value from an HSE error
 * @err:   error value returned from an HSE API entry point
 */
int
hse_err_to_errno(hse_err_t err);

/**
 * hse_params_create() - create a params object
 * @params: configuration parameters
 *
 * Returns EINVAL params==NULL, ENOMEM if memory allocation fails.
 */
hse_err_t
hse_params_create(struct hse_params **params);

/**
 * hse_params_from_file() - parse params from a file
 * @params:  configuration parameters
 * @path:    absolute path to config file
 *
 * Returns EINVAL for invalid configurations.
 */
hse_err_t
hse_params_from_file(struct hse_params *params, const char *path);

/**
 * hse_params_from_string() - parse params from a string
 * @params:  configuration parameters
 * @input:   buffer with configuration
 *
 * Returns EINVAL for invalid configurations.
 */
hse_err_t
hse_params_from_string(struct hse_params *params, const char *input);

/**
 * hse_params_set() - set configuration parameter
 * @params: configuration parameters
 * @key:    target key
 * @val:    target value
 *
 * The following syntax is supported for keys:
 *   kvdb.<param>
 *   kvs.<param>
 *   kvs.<kvs_name>.<param>
 *
 * Returns ENIVAL or ENOSPC on failure. Error message may be
 * retrieved from hse_params_err().
 */
hse_err_t
hse_params_set(struct hse_params *params, const char *key, const char *val);

/**
 * hse_params_get() - get configuration parameter
 * @params:   fixed configuration parameters
 * @key:      target key
 * @buf:      output buffer
 * @buf_sz:   size of buffer
 * @param_sz: if non-NULL this will be set to the actual parameter length + 1
*
 * Returns NULL for invalid inputs or missing keys. Otherwise
 * returns a pointer to provided buffer.
 */
char *
hse_params_get(
    struct hse_params *params,
    const char *       key,
    char *             buf,
    size_t             buf_sz,
    size_t *           param_sz);

/**
 * hse_params_destroy() - destroy params object
 * @params: configuration parameters
 */
void
hse_params_destroy(struct hse_params *params);

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "hse_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
