/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse

#include <mpool/mpool.h>

#include <hse/hse.h>
#include <hse/hse_experimental.h>
#include <hse/kvdb_perfc.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_ctxn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/wp.h>
#include <hse_ikvdb/hse_params_internal.h>

#include <hse/hse_version.h>

#include <hse_util/platform.h>
#include <hse_util/rest_api.h>
#include <hse_util/logging.h>
#include <hse_util/string.h>

#include <unistd.h>
#include <sys/types.h>

static HSE_ALWAYS_INLINE u64
kvdb_lat_startu(const u32 cidx)
{
    return perfc_lat_startu(&kvdb_pkvdbl_pc, cidx);
}

static HSE_ALWAYS_INLINE void
kvdb_lat_record(const u32 cidx, const u64 start)
{
    perfc_lat_record(&kvdb_pkvdbl_pc, cidx, start);
}

/* Accessing hse_initialized is not thread safe, but it is only used
 * in hse_kvdb_init() and hse_kvdb_fini(), which must be serialized
 * with all other HSE APIs.
 */
static bool hse_initialized = false;

const char *
hse_kvdb_version_string(void)
{
    return hse_version;
}

const char *
hse_kvdb_version_tag(void)
{
    return hse_tag;
}

const char *
hse_kvdb_version_sha(void)
{
    return hse_sha;
}

hse_err_t
hse_kvdb_init(void)
{
    merr_t err;

    if (hse_initialized)
        return 0;

    err = hse_platform_init();
    if (err)
        return merr_to_hse_err(err);

    err = ikvdb_init();
    if (err) {
        hse_platform_fini();

        return merr_to_hse_err(err);
    }

    hse_log(HSE_INFO "%s, version %s", HSE_KVDB_DESC, hse_version);

    hse_initialized = true;

    return 0;
}

void
hse_kvdb_fini(void)
{
    if (!hse_initialized)
        return;

    ikvdb_fini();
    rest_server_stop();
    hse_platform_fini();
    hse_initialized = false;
}

hse_err_t
hse_kvdb_make(const char *mpool_name, const struct hse_params *params)
{
    struct kvdb_cparams dbparams;
    struct mpool_params mparams;
    struct mpool *      ds;
    merr_t              err;
    u64                 oid1, oid2;
    u64                 tstart;

    if (HSE_UNLIKELY(!mpool_name))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_MAKE);

    err = hse_params_to_kvdb_cparams(params, NULL, &dbparams);
    if (ev(err))
        return merr_to_hse_err(err);

    err = kvdb_cparams_validate(&dbparams);
    if (ev(err))
        return merr_to_hse_err(err);

    err = mpool_open(mpool_name, O_RDWR | O_EXCL, &ds, NULL);
    if (ev(err))
        return merr_to_hse_err(err);

    err = mpool_params_get(ds, &mparams, NULL);
    if (ev(err))
        goto errout;

    err = uuid_is_null(mparams.mp_utype) ? 0 : merr(EEXIST);
    if (ev(err))
        goto errout;

    for (int i = 0; i < MP_MED_NUMBER; i++) {
        struct mpool_mclass_props mcprops;

        err = mpool_mclass_get(ds, i, &mcprops);
        if (merr_errno(err) == ENOENT)
            continue;
        else if (err)
            goto errout;

        err = mcprops.mc_mblocksz == 32 ? 0 : merr(EINVAL);
        if (ev(err))
            goto errout;
    }

    err = mpool_mdc_get_root(ds, &oid1, &oid2);
    if (ev(err))
        goto errout;

    err = ikvdb_make(ds, oid1, oid2, &dbparams, MPOOL_ROOT_LOG_CAP);
    if (ev(err))
        goto errout;

    memcpy(mparams.mp_utype, &hse_mpool_utype, sizeof(mparams.mp_utype));

    err = mpool_params_set(ds, &mparams, NULL);
    if (ev(err))
        goto errout;

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_MAKE, tstart);

errout:
    mpool_close(ds);

    return merr_to_hse_err(err);
}

static merr_t
handle_rparams(struct kvdb_rparams *params)
{
    perfc_verbosity = params->perfc_enable;

    if (params->log_lvl <= 7)
        hse_log_set_pri((int)params->log_lvl);

    hse_log_set_squelch_ns(params->log_squelch_ns);

    return 0;
}

hse_err_t
hse_kvdb_open(const char *mpool_name, const struct hse_params *params, struct hse_kvdb **handle)
{
    merr_t              err;
    struct ikvdb *      ikvdb;
    struct mpool *      kvdb_ds;
    struct kvdb_rparams rparams;
    u64                 tstart;

    if (HSE_UNLIKELY(!mpool_name || !handle))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_OPEN);

    err = hse_params_to_kvdb_rparams(params, NULL, &rparams);
    if (ev(err))
        return merr_to_hse_err(err);

    err = kvdb_rparams_validate(&rparams);
    if (ev(err))
        return merr_to_hse_err(err);

    handle_rparams(&rparams);

    /* Need write access in case recovery data needs to be replayed into cN.
     * Need exclusive access to prevent multiple applications from
     * working on the same KVDB, which would cause corruption.
     */
    err = mpool_open(mpool_name, O_RDWR | O_EXCL, &kvdb_ds, NULL);
    if (ev(err))
        return merr_to_hse_err(err);

    for (int i = 0; i < MP_MED_NUMBER; i++) {
        struct mpool_mclass_props mcprops;

        err = mpool_mclass_get(kvdb_ds, i, &mcprops);
        if (merr_errno(err) == ENOENT)
            continue;
        else if (err)
            goto close_ds;

        err = mcprops.mc_mblocksz == 32 ? 0 : merr(EINVAL);
        if (ev(err))
            goto close_ds;
    }

    err = ikvdb_open(mpool_name, kvdb_ds, params, &ikvdb);
    if (ev(err))
        goto close_ds;

    *handle = (struct hse_kvdb *)ikvdb;

    if (rparams.read_only == 0) {
        char   sock[PATH_MAX];
        size_t n;

        n = snprintf(sock, sizeof(sock), "%s/%s/%s.sock", REST_SOCK_ROOT, mpool_name, mpool_name);

        if (n >= sizeof(sock)) {
            hse_log(
                HSE_WARNING "Could not start rest server. Socket path was "
                            "truncated: %s",
                sock);
            return 0;
        }

        err = rest_server_start(sock);
        if (ev(err))
            hse_log(HSE_WARNING "Could not start rest server on %s", sock);
        else
            hse_log(HSE_INFO "Rest server started: %s", sock);
    }

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_OPEN, tstart);

    return 0;

close_ds:
    mpool_close(kvdb_ds);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_close(struct hse_kvdb *handle)
{
    merr_t        err = 0, err2 = 0;
    struct mpool *ds;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_CLOSE);

    /* Retrieve mpool descriptor before ikvdb_impl is free'd */
    ds = ikvdb_mpool_get((struct ikvdb *)handle);

    err = ikvdb_close((struct ikvdb *)handle);
    ev(err);

    err2 = mpool_close(ds);
    ev(err2);

    return err ? merr_to_hse_err(err) : merr_to_hse_err(err2);
}

hse_err_t
hse_kvdb_get_names(struct hse_kvdb *handle, unsigned int *count, char ***kvs_list)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !kvs_list))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_GET_NAMES);

    err = ikvdb_get_names((struct ikvdb *)handle, count, kvs_list);
    ev(err);

    return merr_to_hse_err(err);
}

void
hse_kvdb_free_names(struct hse_kvdb *handle, char **kvsv)
{
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_FREE_NAMES);

    ikvdb_free_names((struct ikvdb *)handle, kvsv);
}

hse_err_t
hse_kvdb_kvs_make(struct hse_kvdb *handle, const char *kvs_name, const struct hse_params *params)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_MAKE);

    err = validate_kvs_name(kvs_name);
    ev(err);

    if (!err) {
        err = ikvdb_kvs_make((struct ikvdb *)handle, kvs_name, params);
        ev(err);
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_drop(struct hse_kvdb *handle, const char *kvs_name)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !kvs_name))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_DROP);

    err = ikvdb_kvs_drop((struct ikvdb *)handle, kvs_name);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_open(
    struct hse_kvdb *        handle,
    const char *             kvs_name,
    const struct hse_params *params,
    struct hse_kvs **        kvs_out)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || !kvs_name || !kvs_out))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_start(&kvdb_pkvdbl_pc);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_OPEN);

    err = ikvdb_kvs_open((struct ikvdb *)handle, kvs_name, params, IKVS_OFLAG_NONE, kvs_out);
    ev(err);

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVS_OPEN, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_kvs_close(struct hse_kvs *handle)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_KVS_CLOSE);

    err = ikvdb_kvs_close((struct hse_kvs *)handle);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_put(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            key,
    size_t                  key_len,
    const void *            val,
    size_t                  val_len)
{
    struct kvs_ktuple kt;
    struct kvs_vtuple vt;
    merr_t            err;

    if (HSE_UNLIKELY(!handle || !key || (val_len > 0 && !val)))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KLEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    if (HSE_UNLIKELY(key_len == 0))
        return merr_to_hse_err(merr(ENOENT));

    if (HSE_UNLIKELY(val_len > HSE_KVS_VLEN_MAX))
        return merr_to_hse_err(merr(EMSGSIZE));

    kvs_ktuple_init_nohash(&kt, key, key_len);
    kvs_vtuple_init(&vt, (void *)val, val_len);

    err = ikvdb_kvs_put(handle, os, &kt, &vt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_PUT,
                        PERFC_RA_KVDBOP_KVS_PUTB, key_len + val_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_get(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            key,
    size_t                  key_len,
    bool *                  found,
    void *                  valbuf,
    size_t                  valbuf_sz,
    size_t *                val_len)
{
    struct kvs_ktuple   kt;
    struct kvs_buf      vbuf;
    enum key_lookup_res res;
    merr_t              err;

    if (HSE_UNLIKELY(!handle || !key || !found || !val_len))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(!valbuf && valbuf_sz > 0))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KLEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    if (HSE_UNLIKELY(key_len == 0))
        return merr_to_hse_err(merr(ENOENT));

    /* If valbuf is NULL and valbuf_sz is zero, this call is meant as a
     * probe for the existence of the key and length of its value. To
     * prevent c0/cn from allocating a new buffer for the value, set valbuf
     * to non-zero and proceed.
     */
    if (!valbuf && valbuf_sz == 0)
        valbuf = (void *)-1;

    kvs_ktuple_init_nohash(&kt, key, key_len);
    kvs_buf_init(&vbuf, valbuf, valbuf_sz);

    err = ikvdb_kvs_get(handle, os, &kt, &res, &vbuf);
    if (ev(err))
        return merr_to_hse_err(err);

    /* If the key is found then vbuf.b_len contains the length of the value
     * stored in the kvs.  We expect it to fit into output buffer.
     */
    *found = (res == FOUND_VAL);
    *val_len = vbuf.b_len;

    if (ev(res == FOUND_MULTIPLE))
        return merr_to_hse_err(merr(EPROTO));

    PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_GET,
                    PERFC_RA_KVDBOP_KVS_GETB, *found ? *val_len : 0);

    return 0;
}

/**
 * hse_kvs_delete() - remove the supplied key and associated value from the KVS
 */
hse_err_t
hse_kvs_delete(struct hse_kvs *handle, struct hse_kvdb_opspec *os, const void *key, size_t key_len)
{
    merr_t            err = 0;
    struct kvs_ktuple kt;

    if (HSE_UNLIKELY(!handle || !key))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_KLEN_MAX))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    if (HSE_UNLIKELY(key_len == 0))
        return merr_to_hse_err(merr(ENOENT));

    kvs_ktuple_init_nohash(&kt, key, key_len);
    err = ikvdb_kvs_del(handle, os, &kt);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_DEL,
                        PERFC_RA_KVDBOP_KVS_DELB, key_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_prefix_delete(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            prefix_key,
    size_t                  key_len,
    size_t *                kvs_pfx_len)
{
    merr_t            err;
    struct kvs_ktuple kt;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    if (os && (((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    if (HSE_UNLIKELY(key_len > HSE_KVS_MAX_PFXLEN))
        return merr_to_hse_err(merr(ENAMETOOLONG));

    kvs_ktuple_init(&kt, prefix_key, key_len);

    err = ikvdb_kvs_prefix_delete(handle, os, &kt, kvs_pfx_len);
    ev(err);

    if (!err)
        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_PFX_DEL,
                        PERFC_RA_KVDBOP_KVS_PFX_DELB, key_len);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_sync(struct hse_kvdb *handle)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_startl(&kvdb_pkvdbl_pc, PERFC_SL_PKVDBL_KVDB_SYNC);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_SYNC);

    err = ikvdb_sync((struct ikvdb *)handle);
    ev(err);

    perfc_sl_record(&kvdb_pkvdbl_pc, PERFC_SL_PKVDBL_KVDB_SYNC, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_flush(struct hse_kvdb *handle)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    tstart = perfc_lat_startu(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_FLUSH);
    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_FLUSH);

    err = ikvdb_flush((struct ikvdb *)handle);
    ev(err);

    perfc_lat_record(&kvdb_pkvdbl_pc, PERFC_LT_PKVDBL_KVDB_FLUSH, tstart);

    return merr_to_hse_err(err);
}

struct hse_kvdb_txn *
hse_kvdb_txn_alloc(struct hse_kvdb *handle)
{
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ALLOC);

    return ikvdb_txn_alloc((struct ikvdb *)handle);
}

void
hse_kvdb_txn_free(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_FREE);

    ikvdb_txn_free((struct ikvdb *)handle, txn);
}

hse_err_t
hse_kvdb_txn_begin(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    if (HSE_UNLIKELY(!handle || !txn))
        return merr_to_hse_err(merr(EINVAL));

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_BEGIN);

    err = ikvdb_txn_begin((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_BEGIN, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_txn_commit(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_COMMIT);

    err = ikvdb_txn_commit((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_COMMIT, tstart);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_txn_abort(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    merr_t err;
    u64    tstart;

    tstart = kvdb_lat_startu(PERFC_LT_PKVDBL_KVDB_TXN_ABORT);
    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_ABORT);

    err = ikvdb_txn_abort((struct ikvdb *)handle, txn);
    ev(err);

    kvdb_lat_record(PERFC_LT_PKVDBL_KVDB_TXN_ABORT, tstart);

    return merr_to_hse_err(err);
}

enum hse_kvdb_txn_state
hse_kvdb_txn_get_state(struct hse_kvdb *handle, struct hse_kvdb_txn *txn)
{
    enum hse_kvdb_txn_state state = 0;
    enum kvdb_ctxn_state    istate;
    struct kvdb_ctxn *      ctxn = kvdb_ctxn_h2h(txn);

    perfc_inc(&kvdb_pc, PERFC_RA_KVDBOP_KVDB_TXN_GET_STATE);

    istate = kvdb_ctxn_get_state(ctxn);

    switch (istate) {
        case KVDB_CTXN_ACTIVE:
            state = HSE_KVDB_TXN_ACTIVE;
            break;

        case KVDB_CTXN_COMMITTED:
            state = HSE_KVDB_TXN_COMMITTED;
            break;

        case KVDB_CTXN_ABORTED:
            state = HSE_KVDB_TXN_ABORTED;
            break;

        default:
            state = HSE_KVDB_TXN_INVALID;
            break;
    }

    return state;
}

hse_err_t
hse_kvs_cursor_create(
    struct hse_kvs *        handle,
    struct hse_kvdb_opspec *os,
    const void *            prefix,
    size_t                  pfx_len,
    struct hse_kvs_cursor **cursor)
{
    merr_t err;

    if (HSE_UNLIKELY(!handle || !cursor || (pfx_len && !prefix)))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_CREATE);

    err = ikvdb_kvs_cursor_create(handle, os, prefix, pfx_len, cursor);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_update(struct hse_kvs_cursor *cursor, struct hse_kvdb_opspec *os)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_UPDATE);

    err = ikvdb_kvs_cursor_update(cursor, os);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_seek(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *os,
    const void *            key,
    size_t                  len,
    const void **           found,
    size_t *                flen)
{
    struct kvs_ktuple kt;
    merr_t            err;

    if (HSE_UNLIKELY(!cursor))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_SEEK);

    kt.kt_len = 0;
    err = ikvdb_kvs_cursor_seek(cursor, os, key, len, 0, 0, found ? &kt : 0);
    ev(err);

    if (found && flen && !err) {
        *found = kt.kt_data;
        *flen = kt.kt_len;
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_seek_range(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *os,
    const void *            key,
    size_t                  key_len,
    const void *            limit,
    size_t                  limit_len,
    const void **           found,
    size_t *                flen)
{
    struct kvs_ktuple kt;
    merr_t            err;

    if (HSE_UNLIKELY(!cursor))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_SEEK);

    kt.kt_len = 0;
    err = ikvdb_kvs_cursor_seek(cursor, os, key, key_len, limit, limit_len, found ? &kt : 0);
    ev(err);

    if (found && flen && !err) {
        *found = kt.kt_data;
        *flen = kt.kt_len;
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_read(
    struct hse_kvs_cursor * cursor,
    struct hse_kvdb_opspec *os,
    const void **           key,
    size_t *                klen,
    const void **           val,
    size_t *                vlen,
    bool *                  eof)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor || !key || !klen || !val || !vlen || !eof))
        return merr_to_hse_err(merr(EINVAL));

    if (os && HSE_UNLIKELY(((os->kop_opaque >> 16) != 0xb0de) || ((os->kop_opaque & 0x0000ffff) != 1)))
        return merr_to_hse_err(merr(EINVAL));

    err = ikvdb_kvs_cursor_read(cursor, os, key, klen, val, vlen, eof);
    ev(err);

    if (!err && !*eof) {
        PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_READ,
                        PERFC_RA_KVDBOP_KVS_GETB, *klen + *vlen);
    }

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvs_cursor_destroy(struct hse_kvs_cursor *cursor)
{
    merr_t err;

    if (HSE_UNLIKELY(!cursor))
        return merr_to_hse_err(merr(EINVAL));

    PERFC_INC_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_CURSOR_DESTROY);

    err = ikvdb_kvs_cursor_destroy(cursor);
    ev(err);

    return merr_to_hse_err(err);
}

hse_err_t
hse_kvdb_compact(struct hse_kvdb *handle, int flags)
{
    if (HSE_UNLIKELY(!handle))
        return merr_to_hse_err(merr(EINVAL));

    ikvdb_compact((struct ikvdb *)handle, flags);

    return 0;
}

hse_err_t
hse_kvdb_compact_status_get(struct hse_kvdb *handle, struct hse_kvdb_compact_status *status)
{
    if (HSE_UNLIKELY(!handle || !status))
        return merr_to_hse_err(merr(EINVAL));

    memset(status, 0, sizeof(*status));
    ikvdb_compact_status_get((struct ikvdb *)handle, status);

    return 0;
}

char *
hse_err_to_string(hse_err_t err, char *buf, size_t buf_sz, size_t *need_sz)
{
    return merr_strinfo(err, buf, buf_sz, need_sz);
}

int
hse_err_to_errno(hse_err_t err)
{
    return merr_errno(err);
}

/* Includes necessary files for mocking */
#if HSE_MOCKING
#include "hse_ut_impl.i"
#include "mpool_ut_impl.i"
#endif /* HSE_MOCKING */
