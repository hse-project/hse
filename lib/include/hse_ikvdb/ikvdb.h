/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_API_H
#define HSE_IKVDB_API_H

#include <hse/flags.h>

#include <hse_ikvdb/tuple.h>
#include <hse_ikvdb/diag_kvdb.h>

#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/perfc.h>
#include <hse_util/workqueue.h>

#include <bsd/libutil.h>

/* MTF_MOCK_DECL(ikvdb) */

#define HSE_KVDB_SYNC_REFWAIT HSE_KVDB_SYNC_RSVD1

struct yaml_context;

struct config;
struct ikvdb;
struct ikvdb_impl;
struct kvdb_txn;
struct kvdb_meta;
struct kvdb_rparams;
struct kvdb_cparams;
struct kvs_rparams;
struct kvs_cparams;
struct hse_kvdb_opspec;
struct hse_kvs_cursor;
struct mpool;
struct c0sk;
struct cndb;
struct kvdb_diag_kvs_list;
struct kvs;
struct ikvdb_kvs_hdl;
enum mpool_mclass;

struct hse_kvdb_txn {
};

#define HSE_KVDB_DESC      "Heterogeneous-memory Storage Engine KVDB"

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
 * ikvdb_create() - create a new KVDB instance within the named mpool
 * @kvdb_home: KVDB home
 * @params:    fixed configuration parameters
 * @captgt:    captgt of the mdc
 * @pmem_only: is it a pmem-only KVDB
 */
merr_t
ikvdb_create(const char *kvdb_home, struct kvdb_cparams *params, bool pmem_only);

/**
 * Drop a KVDB
 *
 * Drops files managed by the KVDB such as the kvdb.meta file
 *
 * @param kvdb_home: KVDB home
 */
merr_t
ikvdb_drop(const char *kvdb_home);

/** @brief Get media class information from a KVDB.
 *
 * @param kvdb: KVDB handle.
 * @param mclass: Media class.
 * @param info: Media class information object.
 *
 * @returns Error status.
 */
merr_t
ikvdb_mclass_info_get(struct ikvdb *kvdb, enum hse_mclass mclass, struct hse_mclass_info *info);

/**
 * Add media class to a KVDB
 *
 * @param kvdb_home: KVDB home
 * @param params:    configuration parameters
 */
merr_t
ikvdb_storage_add(const char *kvdb_home, struct kvdb_cparams *params);

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
 * @kvdb_home:      kvdb home
 * @pfh:            PID file handle
 * @mp:             mpool handle
 * @params:         parameters that affect how the KVDB will be used
 * @handle:         (output) handle to access the opened KVDB
 */
merr_t
ikvdb_diag_open(
    const char *         kvdb_home,
    struct kvdb_rparams *params,
    struct ikvdb **      handle);

/**
 * ikvdb_diag_close() - close relevant data streams with minimial processing
 * @handle:         handle to the opened KVDB
 */
merr_t
ikvdb_diag_close(struct ikvdb *handle);

/**
 * ikvdb_open() - prepare HSE KVDB target for subsequent use by the application
 * @kvdb_home:   kvdb home
 * @params:      kvdb rparams
 * @kvdb:        (output) handle to access the opened KVDB
 */
merr_t
ikvdb_open(
    const char *         kvdb_home,
    struct kvdb_rparams *params,
    struct ikvdb **      kvdb);

#define IKVS_OFLAG_NONE   0
#define IKVS_OFLAG_REPLAY 1 /* used when wal opens ikvs/kvs/cn for replay */

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
    struct ikvdb *      kvdb,
    const char *        kvs_name,
    struct kvs_rparams *rparams,
    uint                ikvs_oflags,
    struct hse_kvs **   kvs_out);

/**
 * ikvdb_pidfh() - get the PID file handle associated with the KVDB
 * @kvdb: kvdb handle
 */
struct pidfh *
ikvdb_pidfh(struct ikvdb *kvdb);

/**
 * Attach a pidfile to the lifetime of the KVDB
 *
 * @param kvdb: KVDB handle
 * @param pfh: pidfile handle
 */
void
ikvdb_pidfh_attach(struct ikvdb *kvdb, struct pidfh *pfh);

/**
 * ikvdb_home() - get the home directory
 * @kvdb: kvdb handle
 */
/* MTF_MOCK */
const char *
ikvdb_home(struct ikvdb *kvdb);

/** @brief Get the KVDB alias.
 *
 * The alias is a way to reference a KVDB without needing the home directory.
 * The alias is useful in contexts like data tree or REST paths. The pointer to
 * the alias will be valid for the entire lifetime of the KVDB.
 *
 * @param kvdb: KVDB handle.
 *
 * @returns KVDB alias.
 */
/* MTF_MOCK */
const char *
ikvdb_alias(struct ikvdb *kvdb);

/**
 * ikvdb_home() - get the config object
 * @kvdb: kvdb handle
 */
struct config *
ikvdb_config(struct ikvdb *kvdb);

/** @brief Get KVDB rparams.
 *
 * @param kvdb: KVDB handle.
 *
 * @returns KVDB rparams.
 */
const struct kvdb_rparams * HSE_RETURNS_NONNULL
ikvdb_rparams(struct ikvdb *kvdb);

/**
 * Attach a config object to the lifetime of the KVDB
 *
 * @param kvdb: KVDB handle
 * @param conf: Config handle
 */
void
ikvdb_config_attach(struct ikvdb *kvdb, struct config *conf);

/**
 * ikvdb_read_only() - is the KVDB read only?
 * @kvdb:       kvdb handle
 */
/* MTF_MOCK */
bool
ikvdb_read_only(struct ikvdb *kvdb);

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

merr_t
ikvdb_param_get(
    struct ikvdb *kvdb,
    const char *  param,
    char *        buf,
    size_t        buf_sz,
    size_t *      needed_sz);

/**
 * ikvdb_kvs_names_get() -
 * @param kvdb: handle to the KVDB
 * @param[out] count: number of KVSes in the KVDB
 * @param[out] namev: array of KVS names, caller must free with ikvdb_kvs_names_free()
 */
merr_t
ikvdb_kvs_names_get(struct ikvdb *kvdb, size_t *namec, char ***namev);

/**
 * ikvdb_kvs_names_free() -
 * @param kvdb: handle to the KVDB
 * @param namev: array of buffers that ikvdb_kvs_names_get() populated
 */
void
ikvdb_kvs_names_free(struct ikvdb *kvdb, char **namev);

/**
 * ikvdb_kvs_count() - Get the number of KVSes in the KVDB
 * @kvdb:   KVDB handle
 * @count:  (output) number of KVSes
 */
void
ikvdb_kvs_count(struct ikvdb *kvdb, unsigned int *count);

/**
 * ikvdb_kvs_create() - allow a new KVS to be created within a KVDB
 * @kvdb:      KVDB handle
 * @kvs_name:  KVS name
 * @params:    KVS cparams
 */
merr_t
ikvdb_kvs_create(struct ikvdb *kvdb, const char *kvs_name, const struct kvs_cparams *params);

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
    unsigned int             flags,
    struct hse_kvdb_txn *    txn,
    struct kvs_ktuple *      kt,
    struct kvs_vtuple       *vt);

/**
 * ikvdb_kvs_get() - search for the given key within the KVS. HSE allocates
 * memory for the result if vbuf->b_buf is NULL.
 */
merr_t
ikvdb_kvs_get(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    struct kvs_ktuple *  kt,
    enum key_lookup_res *res,
    struct kvs_buf *     vbuf);

/**
 * ikvdb_kvs_del() - remove the supplied key and associated value from the KVS
 * indexed by opspec->kop_index.
 */
/* MTF_MOCK */
merr_t
ikvdb_kvs_del(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    struct kvs_ktuple *  kt);

/* MTF_MOCK */
merr_t
ikvdb_kvs_pfx_probe(
    struct hse_kvs *     handle,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    struct kvs_ktuple *  kt,
    enum key_lookup_res *res,
    struct kvs_buf *     kbuf,
    struct kvs_buf *     vbuf);

/**
 * ikvdb_kvs_prefix_delete() - remove all key/value pairs with the given prefix
 * from the KVS indexed by opspec->kop_index. If a prefix scan is in progress
 * for a matching prefix, the scan can fail after the kvdb_prefix_delete().
 */
/* MTF_MOCK */
merr_t
ikvdb_kvs_prefix_delete(
    struct hse_kvs *     kvs,
    unsigned int         flags,
    struct hse_kvdb_txn *txn,
    struct kvs_ktuple *  kt);

merr_t
ikvdb_kvs_param_get(
    struct hse_kvs *kvs,
    const char *    param,
    char *          buf,
    size_t          buf_sz,
    size_t *        needed_sz);

/**
 * ikvdb_sync() - sync data in all of the KVSes to stable media.
 */
merr_t
ikvdb_sync(struct ikvdb *kvdb, unsigned int flags);

/**
 * ikvdb_horizon() - return an upper bound on the smallest view sequence
 *                   number in use by any currently active transaction,
 *                   get, or scan operation.
 */
u64
ikvdb_horizon(struct ikvdb *store);

/**
 * ikvdb_txn_horizon() - return an upper bound on the smallest view sequence
 *                   number in use by any currently active transaction.
 */
u64
ikvdb_txn_horizon(struct ikvdb *store);

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
    unsigned int            flags,
    struct hse_kvdb_txn *   txn,
    const void *            prefix,
    size_t                  pfx_len,
    struct hse_kvs_cursor **cursor);

/**
 * ikvdb_kvs_cursor_update() - incorporate updates since cursor created
 */
merr_t
ikvdb_kvs_cursor_update_view(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags);

/**
 * ikvdb_kvs_cursor_seek() - move the cursor to the closet match to @key.
 * The next ikvdb_kvs_cursor_read() will resume at this point.
 */
merr_t
ikvdb_kvs_cursor_seek(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void *           key,
    size_t                 key_len,
    const void *           limit,
    size_t                 limit_len,
    struct kvs_ktuple *    kt);

/**
 * ikvdb_kvs_cursor_read() - iteratively access the elements pointed to by
 * cursor
 */
merr_t
ikvdb_kvs_cursor_read(
    struct hse_kvs_cursor *cursor,
    unsigned int           flags,
    const void **          key,
    size_t *               key_len,
    const void **          val,
    size_t *               val_len,
    bool *                 eof);

merr_t
ikvdb_kvs_cursor_read_copy(
    struct hse_kvs_cursor *cur,
    unsigned int           flags,
    void *                 keybuf,
    size_t                 keybuf_sz,
    size_t *               key_len,
    void *                 valbuf,
    size_t                 valbuf_sz,
    size_t *               val_len,
    bool *                 eof);

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
ikvdb_compact_status_get(struct ikvdb *handle, struct hse_kvdb_compact_status *status);

/**
 * ikvdb_kvdb_handle()    - Convert an ikvdb reference to an ikvdb
 * @self:                 - ikvdb_imple reference
 */
/* MTF_MOCK */
struct ikvdb *
ikvdb_kvdb_handle(struct ikvdb_impl *self);

/**
 * ikvdb_kvs_query_tree() - get cn tree shape and write to fd
 * @kvs:  kvs handle
 * @yc:   yaml context
 * @fd:   output file descriptor
 * @list: whether or not to list kblock and vblock ids
 */
merr_t
ikvdb_kvs_query_tree(struct hse_kvs *kvs, struct yaml_context *yc, int fd, bool list);

uint32_t
ikvdb_lowmem_scale(uint32_t memgb);

merr_t
ikvdb_pmem_only_from_cparams(
    const char                *kvdb_home,
    const struct kvdb_cparams *cparams,
    bool                      *pmem_only);


/*
 * [HSE_REVISIT] - This whole callback setup up needs to be reworked.
 *                Huge layering violations, etc.
 */

/**
 * struct kvdb_callback - Providing callbacks for cN ingest.
 * @kc_cbarg:       opaque subscriber specific argument
 * @kc_cningest_cb: supplies cN ingest status
 */
struct kvdb_callback {
    struct ikvdb *kc_cbarg;
    void (*kc_cningest_cb)(struct ikvdb *ikdb, uint64_t seqno, uint64_t gen,
			   uint64_t txhorizon, bool post_ingest);
    void (*kc_bufrel_cb)(struct ikvdb *ikdb, uint64_t gen);
};

/*
 * WAL replay routines
 */

merr_t
ikvdb_wal_replay_open(struct ikvdb *ikvdb, struct ikvdb_kvs_hdl **ikvsh_out);

void
ikvdb_wal_replay_close(struct ikvdb *ikvdb, struct ikvdb_kvs_hdl *ikvsh);

merr_t
ikvdb_wal_replay_put(
    struct ikvdb         *ikvdb,
    struct ikvdb_kvs_hdl *ikvsh,
    u64                   cnid,
    u64                   seqno,
    struct kvs_ktuple    *kt,
    struct kvs_vtuple    *vt);

merr_t
ikvdb_wal_replay_del(
    struct ikvdb         *ikvdb,
    struct ikvdb_kvs_hdl *ikvsh,
    u64                   cnid,
    u64                   seqno,
    struct kvs_ktuple    *kt);

merr_t
ikvdb_wal_replay_prefix_del(
    struct ikvdb         *ikvdb,
    struct ikvdb_kvs_hdl *ikvsh,
    u64                   cnid,
    u64                   seqno,
    struct kvs_ktuple    *kt);

void
ikvdb_wal_replay_seqno_set(struct ikvdb *ikvdb, uint64_t seqno);

void
ikvdb_wal_replay_gen_set(struct ikvdb *ikvdb, u64 gen);

bool
ikvdb_wal_replay_size_set(struct ikvdb *ikvdb, struct ikvdb_kvs_hdl *ikvsh, uint64_t mem_sz);

void
ikvdb_wal_replay_size_reset(struct ikvdb_kvs_hdl *ikvsh);

void
ikvdb_wal_replay_enable(struct ikvdb *ikvdb);

void
ikvdb_wal_replay_disable(struct ikvdb *ikvdb);

#if HSE_MOCKING
#include "ikvdb_ut.h"
#endif /* HSE_MOCKING */

#endif
