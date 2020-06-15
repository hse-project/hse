/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_API_H
#define HSE_IKVDB_API_H

#include <hse/hse.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/kvdb_cparams.h>
#include <hse_ikvdb/kvs_cparams.h>
#include <hse_ikvdb/kvs_rparams.h>
#include <hse_ikvdb/diag_kvdb.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/perfc.h>
#include <hse_util/workqueue.h>

/* MTF_MOCK_DECL(ikvdb) */

struct ikvdb;
struct ikvdb_impl;
struct kvdb_txn;
struct kvdb_cparams;
struct kvdb_rparams;
struct hse_kvdb_opspec;
struct kvdb_log;
struct hse_kvs_cursor;
struct mpool;
struct c0sk;
struct cndb;
struct kvdb_diag_kvs_list;
struct c1;

struct kvs;

struct hse_kvdb_txn {
};

/**
 * struct kvdb_bak_work
 * @bak_work:
 * @bak_kvs:
 * @bak_fname: data file name
 * @bak_cur: cursor for export
 * @bak_fcnt: number of dumped data files for this kvs
 * @bak_kvcnt: number of k-v pairs in this kvs
 * @bak_err:
 */
struct kvdb_bak_work {
    struct work_struct     bak_work;
    struct hse_kvs *       bak_kvs;
    char                   bak_fname[PATH_MAX];
    struct hse_kvs_cursor *bak_cur;
    int                    bak_fcnt;
    u64                    bak_kvcnt;
    merr_t                 bak_err;
};

/**
 * struct kvs_import
 * @kvsi_params: kvs create time parameters
 * @kvsi_name: kvs name
 * @kvsi_kvcnt: number of k-v pairs in this kvs
 * @kvsi_fcnt: number of data files dumped drung kvdb export
 */
struct kvs_import {
    struct hse_params *kvsi_params;
    char               kvsi_name[HSE_KVS_NAME_LEN_MAX];
    u64                kvsi_kvcnt;
    u64                kvsi_fcnt;
    struct hse_kvs *   kvsi_kvs;
};

#define IKVDB_SUB_NAME_SEP ":"
#define HSE_KVDB_DESC "Heterogeneous-memory Storage Engine KVDB"

/**
 * ikvdb_init() - prepare the ikvdb subsystem for use
 */
extern merr_t
ikvdb_init(void);

/**
 * ikvdb_fini() - prepare the ikvdb subsystem for being unloaded
 */
extern void
ikvdb_fini(void);

/**
 * validate_kvs_name() - check the validity of a kvs name
 * @kvs_name: candidate kvs name
 */
merr_t
validate_kvs_name(const char *kvs_name);

void
kvdb_perfc_register(void *pc);

/**
 * ikvdb_make() - create a new KVDB instance within the named mpool
 * @ds:        dataset descriptor
 * @oid1:      oid of mlog1 of the mdc
 * @oid2:      oid of mlog2 of the mdc
 * @params:    fixed configuration parameters
 * @captgt:    captgt of the mdc
 */
merr_t
ikvdb_make(struct mpool *ds, u64 oid1, u64 oid2, struct kvdb_cparams *params, u64 captgt);

/**
 * ikvdb_diag_cndb() - returns a pointer to kvdb's cndb
 * @handle:         handle to access the opened KVDB
 * @cndb:           (output) pointer to cndb
 */
merr_t
ikvdb_diag_cndb(struct ikvdb *handle, struct cndb **cndb);

/**
 * ikvdb_diag_kvslist() - obtain a list of kvses known to kvdb
 * @handle:       handle to the opened kvdb
 * @list:         pointer to an array of descriptors
 * @len:          the number of descriptors allocated for the array
 * @kvscnt:       (output) the number of kvses known to kvdb
 *
 * If kvscnt > len, the array contains the first len kvses.
 */
merr_t
ikvdb_diag_kvslist(struct ikvdb *handle, struct diag_kvdb_kvs_list *list, int len, int *kvscnt);

/**
 * ikvdb_diag_open() - open relevant media streams with minimal processing
 * @mp_name:        mpool/kvdb name
 * @ds:             dataset descriptor
 * @rparams:        run time parameters that affect how the KVDB will be used
 * @handle:         (output) handle to access the opened KVDB
 */
merr_t
ikvdb_diag_open(
    const char *         mp_name,
    struct mpool *       ds,
    struct kvdb_rparams *rparams,
    struct ikvdb **      handle);

/**
 * ikvdb_diag_close() - close relevant data streams with minimial processing
 * @handle:         handle to the opened KVDB
 */
merr_t
ikvdb_diag_close(struct ikvdb *handle);

/**
 * ikvdb_open() - prepare HSE KVDB target for subsequent use by the application
 * @mp_name:        mpool/kbdb name
 * @ds:             dataset descriptor
 * @params:         run time parameters that affect how the KVDB will be used
 * @kvdb:           (output) handle to access the opened KVDB
 */
merr_t
ikvdb_open(const char *mp_name, struct mpool *ds, struct hse_params *params, struct ikvdb **kvdb);

#define IKVS_OFLAG_NONE 0
#define IKVS_OFLAG_REPLAY 1 /* used when c1 opens ikvs/kvs/cn for replay */

/**
 * ikvdb_kvs_open() - prepare HSE KVDB constituent KVS for subsequent use by
 *                    the application
 * @kvdb:        kvdb handle
 * @kvs_name:    kvs name
 * @rparams:     run time parameters that affect how the KVS will be used
 * @ikvs_oflags: flags to alter ikvs open behavior
 * @kvs_out:     (output) handle to access the opened KVS
 */
merr_t
ikvdb_kvs_open(
    struct ikvdb *     kvdb,
    const char *       kvs_name,
    struct hse_params *params,
    uint               ikvs_oflags,
    struct hse_kvs **  kvs_out);

/**
 * ikvdb_rdonly() - is the KVDB read only?
 * @kvdb:       kvdb handle
 */
/* MTF_MOCK */
bool
ikvdb_rdonly(struct ikvdb *kvdb);

/**
 * ikvdb_kvs_close() - close the KVS
 * @kvs:          kvs handle to close
 */
merr_t
ikvdb_kvs_close(struct hse_kvs *kvs);

/**
 * ikvdb_get_c0sk() - get a handle to the associated structured key c0
 * @kvdb:       kvdb handle
 */
/* MTF_MOCK */
void
ikvdb_get_c0sk(struct ikvdb *kvdb, struct c0sk **out);

/**
 * ikvdb_get_c1() - get a handle to c1
 * @kvdb:       kvdb handle
 * @out:        c1 handle (output)
 */
void
ikvdb_get_c1(struct ikvdb *handle, struct c1 **out);

/**
 * ikvdb_get_sched() - get a handle to the associated scheduler
 */
/* MTF_MOCK */
struct csched *
ikvdb_get_csched(struct ikvdb *handle);

/**
 * ikvdb_get_mclass_policy() - get a handle to the media class policy
 */
/* MTF_MOCK */
struct mclass_policy *
ikvdb_get_mclass_policy(struct ikvdb *handle, const char *name);

/**
 * ikvdb_kvs_get_cn() - retrieve a pointer to the cn
 * @kvs:     kvs handle
 */
struct cn *
ikvdb_kvs_get_cn(struct hse_kvs *kvs);

/**
 * ikvdb_get_names() -
 * @kvdb:     handle to the KVDB
 * @count:    (output)number of KVSes in the KVDB
 * @kvs_list: (output)vector of KVSes. Allocated by the function
 */
merr_t
ikvdb_get_names(struct ikvdb *kvdb, unsigned int *count, char ***kvs_list);

/**
 * ikvdb_free_names() -
 * @kvdb:     handle to the KVDB
 * @kvsv:     array of buffers that kvdb_get_names populated
 */
void
ikvdb_free_names(struct ikvdb *kvdb, char **kvsv);

/**
 * ikvdb_kvs_count() - Get the number of KVSes in the KVDB
 * @kvdb:   KVDB handle
 * @count:  (output) number of KVSes
 */
void
ikvdb_kvs_count(struct ikvdb *kvdb, unsigned int *count);

/**
 * ikvdb_kvs_make() - allow a new KVS to be created within a KVDB
 * @kvdb:      KVDB handle
 * @kvs_name:  KVS name
 * @params:    static configuration parameters for the KVS
 */
merr_t
ikvdb_kvs_make(struct ikvdb *kvdb, const char *kvs_name, struct hse_params *params);

/**
 * ikvdb_kvs_drop() - delete a KVS from the associated KVDB
 * @kvdb:      KVDB handle
 * @kvs_name:  name of the KVS to delete
 */
merr_t
ikvdb_kvs_drop(struct ikvdb *kvdb, const char *kvs_name);

/**
 * ikvdb_close() - indicate that the KVDB will no longer be used
 * @kvdb: KVDB handle
 */
merr_t
ikvdb_close(struct ikvdb *kvdb);

/**
 * ikvdb_mpool_get() - retrieve the mpool descriptor
 * @kvdb: KVDB handle
 */
struct mpool *
ikvdb_mpool_get(struct ikvdb *kvdb);

/**
 * ikvdb_kvs_put() - insert a new key/value pair into the KVS indexed by
 * opspec->kop_index within the KVDB. Any value already associated with the key
 * is overwritten.
 */
/* MTF_MOCK */
merr_t
ikvdb_kvs_put(
    struct hse_kvs *         kvs,
    struct hse_kvdb_opspec * opspec,
    struct kvs_ktuple *      kt,
    const struct kvs_vtuple *vt);

/**
 * ikvdb_kvs_get() - search for the given key within the KVS. HSE allocates
 * memory for the result if vbuf->b_buf is NULL.
 */
merr_t
ikvdb_kvs_get(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    struct kvs_ktuple *     kt,
    enum key_lookup_res *   res,
    struct kvs_buf *        vbuf);

/**
 * ikvdb_kvs_del() - remove the supplied key and associated value from the KVS
 * indexed by opspec->kop_index.
 */
/* MTF_MOCK */
merr_t
ikvdb_kvs_del(struct hse_kvs *kvs, struct hse_kvdb_opspec *opspec, struct kvs_ktuple *kt);

/* MTF_MOCK */
merr_t
ikvdb_kvs_pfx_probe(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    enum key_lookup_res *   res,
    struct kvs_buf *        kbuf,
    struct kvs_buf *        vbuf);

/**
 * ikvdb_kvs_prefix_delete() - remove all key/value pairs with the given prefix
 * from the KVS indexed by opspec->kop_index. If a prefix scan is in progress
 * for a matching prefix, the scan can fail after the kvdb_prefix_delete().
 */
/* MTF_MOCK */
merr_t
ikvdb_kvs_prefix_delete(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    struct kvs_ktuple *     kt,
    size_t *                kvs_pfx_len);

/**
 * ikvdb_sync() - flush data in all of the KVSes to stable media.
 */
merr_t
ikvdb_sync(struct ikvdb *kvdb);

/**
 * ikvdb_flush() - initiate data flush in all of the KVSes to stable media.
 */
/* MTF_MOCK */
merr_t
ikvdb_flush(struct ikvdb *store);

/**
 * ikvdb_horizon() - return an upper bound on the smallest view sequence
 *                   number in use by any currently active transaction,
 *                   get, or scan operation.
 */
u64
ikvdb_horizon(struct ikvdb *store);

/**
 * ikvdb_txn_alloc() - allocate space for a transaction
 */
struct hse_kvdb_txn *
ikvdb_txn_alloc(struct ikvdb *kvdb);

/**
 * ikvdb_txn_free() - free space for a transaction
 */
void
ikvdb_txn_free(struct ikvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * ikvdb_txn_begin() - initiate a transaction. txn->kt_seq_num identifies it.
 */
merr_t
ikvdb_txn_begin(struct ikvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * ikvdb_txn_commit() - publish all mutations performed in the context of txn.
 */
merr_t
ikvdb_txn_commit(struct ikvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * ikvdb_txn_abort() - abort all mutations performed in the context of txn,
 * such that they are not visible in any subsequent access.
 */
merr_t
ikvdb_txn_abort(struct ikvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * ikvdb_txn_state() - retrieve the state of a transaction.
 *
 */
enum kvdb_ctxn_state
ikvdb_txn_state(struct ikvdb *kvdb, struct hse_kvdb_txn *txn);

/**
 * ikvdb_kvs_create_cursor() - return a cursor that may be used to iterate
 * over the elements of a KVS in sorted order. Forward/reverse direction is
 * specified by opspec->kop_flags. A scan is not part of any transaction.
 */
merr_t
ikvdb_kvs_cursor_create(
    struct hse_kvs *        kvs,
    struct hse_kvdb_opspec *opspec,
    const void *            prefix,
    size_t                  pfx_len,
    struct hse_kvs_cursor **cursor);

/**
 * ikvdb_kvs_cursor_update() - incorporate updates since cursor created
 */
merr_t
ikvdb_kvs_cursor_update(struct hse_kvs_cursor *cursor, struct hse_kvdb_opspec *opspec);

/**
 * ikvdb_kvs_cursor_seek() - move the cursor to the closet match to @key.
 * The next ikvdb_kvs_cursor_read() will resume at this point.
 */
merr_t
ikvdb_kvs_cursor_seek(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *opspec,
    const void *            key,
    size_t                  key_len,
    const void *            limit,
    size_t                  limit_len,
    struct kvs_ktuple *     kt);

/**
 * ikvdb_kvs_cursor_read() - iteratively access the elements pointed to by
 * cursor
 */
merr_t
ikvdb_kvs_cursor_read(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *opspec,
    const void **           key,
    size_t *                key_len,
    const void **           val,
    size_t *                val_len,
    bool *                  eof);

/**
 * ikvdb_kvs_cursor_destroy() - allow the caller to indicate that is is done
 * with the scan and release the associated cursor
 */
merr_t
ikvdb_kvs_cursor_destroy(struct hse_kvs_cursor *cursor);

void
ikvdb_compact(struct ikvdb *self, int flags);

/* [HSE_REVISIT] - the ikvdb layer needs its own struct */

struct hse_kvdb_compact_status;

void
ikvdb_compact_status(struct ikvdb *handle, struct hse_kvdb_compact_status *status);

/**
 * ikvdb_kvdb_handle()    - Convert an ikvdb reference to an ikvdb
 * @self:                 - ikvdb_imple reference
 */
/* MTF_MOCK */
struct ikvdb *
ikvdb_kvdb_handle(struct ikvdb_impl *self);

/**
 * ikvdb_set_replaying() - Set c0sk replaying flag.
 * @ikdb: ikvdb handle
 */
void
ikvdb_set_replaying(struct ikvdb *ikdb);

/**
 * ikvdb_unset_replaying()- Unset c0sk replaying flag.
 * @ikdb: ikvdb handle
 */
void
ikvdb_unset_replaying(struct ikvdb *ikdb);

/**
 * ikvdb_diag_c1() - returns a pointer to kvdb's c1
 * @handle:         handle to access the opened KVDB
 * @ingestid:       latest ingest id
 * @c1:             (output) pointer to c1
 */
merr_t
ikvdb_diag_c1(struct ikvdb *handle, u64 ingestid, struct c1 **c1);

/**
 * ikvdb_import() - import kvdb from files
 * @handle: kvdb handle
 * @path:
 */
merr_t
ikvdb_import(struct ikvdb *handle, const char *path);

/**
 * ikvdb_export() - export kvdb into files
 * @handle: kvdb handle
 * @cparams: kvdb create time parameters
 * @path: export destination directory
 */
merr_t
ikvdb_export(struct ikvdb *handle, struct kvdb_cparams *cparams, const char *path);

/**
 * ikvdb_import_kvdb_cparams() - import kvdb meta data from TOC file
 * @path:
 * @kvdb_cparams:
 */
merr_t
ikvdb_import_kvdb_cparams(const char *path, struct kvdb_cparams *kvdb_cparams);

/*
 * [HSE_REVISIT] - This whole callback setup up needs to be reworked.
 *                Huge layering violations, etc.
 */

/**
 * struct kvdb_callback       - Providing callbacks for cN ingest.
 * @kc_cbarg:                   opaque subscriber specific argument
 * @kc_cn_ingest_callback:      supplies cN ingest status
 */
struct kvdb_callback {
    struct ikvdb *kc_cbarg;
    void (*kc_cn_ingest_callback)(
        struct ikvdb *ikdb,
        unsigned long seqno,
        unsigned long status,
        unsigned long cnid,
        const void *  key,
        unsigned int  key_len);
};

/* [HSE_REVISIT] - this stuff all needs to be ripped out */

static __always_inline bool
kvdb_kop_is_priority(const struct hse_kvdb_opspec *os)
{
    return os && (os->kop_flags & HSE_KVDB_KOP_FLAG_PRIORITY);
}

static __always_inline bool
kvdb_kop_is_txn(const struct hse_kvdb_opspec *os)
{
    return os && os->kop_txn;
}

static __always_inline bool
kvdb_kop_is_reverse(const struct hse_kvdb_opspec *os)
{
    return os && (os->kop_flags & HSE_KVDB_KOP_FLAG_REVERSE);
}

static __always_inline bool
kvdb_kop_is_bind_txn(const struct hse_kvdb_opspec *os)
{
    return os && (os->kop_flags & HSE_KVDB_KOP_FLAG_BIND_TXN);
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "ikvdb_ut.h"
#endif /* HSE_UNIT_TEST_MODE */

#endif
