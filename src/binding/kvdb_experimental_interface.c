/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_hse_experimental

#include <hse/hse.h>
#include <hse/hse_experimental.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/hse_params_internal.h>
#include <hse_ikvdb/kvdb_perfc.h>

#include <hse_util/platform.h>

uint64_t
hse_kvdb_export_exp(struct hse_kvdb *handle, struct hse_params *params, const char *path)
{
    merr_t              err;
    struct kvdb_cparams dbparams;

    if (ev(!handle || !path))
        return merr(EINVAL);

    dbparams = hse_params_to_kvdb_cparams(params, NULL);

    err = ikvdb_export((struct ikvdb *)handle, &dbparams, path);
    if (ev(err))
        hse_elog(HSE_ERR "Failed to export kvdb to path %s, @@e", err, path);

    return err;
}

uint64_t
hse_kvdb_import_exp(const char *mpool_name, const char *path)
{
    struct hse_params * params;
    struct hse_kvdb *   handle;
    struct kvdb_cparams dbparams = kvdb_cparams_defaults();
    char                buf[64];
    merr_t              err, err2;

    if (!path || !mpool_name)
        return merr(EINVAL);

    hse_params_create(&params);

    /* Parse kvdb create parameters from dumped TOC file */
    err = ikvdb_import_kvdb_cparams(path, &dbparams);
    if (ev(err, HSE_ERR))
        goto err_exit;

    /* convert kvdb_cparams to hse_params */
    snprintf(buf, sizeof(buf), "%lu", dbparams.dur_capacity);
    err = hse_params_set(params, "kvdb.dur_capacity", buf);
    if (ev(err))
        return err;

    /* Create a brand new kvdb */
    err = hse_kvdb_make(mpool_name, params);
    if (ev(err)) {
        hse_elog(HSE_ERR "Failed to create kvdb %s, @@e", err, mpool_name);
        goto err_exit;
    }

    err = hse_params_set(params, "kvdb.rparams.excl", "true");
    if (ev(err))
        goto err_exit;

    err = hse_kvdb_open(mpool_name, params, &handle);
    if (ev(err)) {
        hse_elog(HSE_ERR "Failed to open kvdb in mpool %s, @@e", err, mpool_name);
        goto err_exit;
    }

    /* At this point we've got an open handle and we're done with params */
    hse_params_destroy(params);

    err = ikvdb_import((struct ikvdb *)handle, path);
    if (ev(err))
        hse_elog(HSE_ERR "Failed to import kvdb in %s to path %s, @@e", err, mpool_name, path);

    /* close the handle regardless of the success/failure of the import */
    err2 = hse_kvdb_close(handle);
    if (ev(err2))
        hse_elog(HSE_ERR "Failed to close kvdb %s, @@e", err2, mpool_name);

    return err ? err : err2;

err_exit:
    hse_params_destroy(params);

    return err;
}

uint64_t
hse_kvs_prefix_probe_exp(
    struct hse_kvs *            handle,
    struct hse_kvdb_opspec *    os,
    const void *                pfx,
    size_t                      pfx_len,
    enum hse_kvs_pfx_probe_cnt *found,
    void *                      keybuf,
    size_t                      keybuf_sz,
    size_t *                    key_len,
    void *                      valbuf,
    size_t                      valbuf_sz,
    size_t *                    val_len)
{
    struct kvs_ktuple   kt;
    struct kvs_buf      kbuf, vbuf;
    enum key_lookup_res res;
    merr_t              err = 0;
    u64                 sum __maybe_unused;

    if (!handle || !pfx || !pfx_len || !found || !val_len)
        err = merr(EINVAL);
    else if (!valbuf && valbuf_sz > 0)
        err = merr(EINVAL);
    else if (pfx_len > HSE_KVS_KLEN_MAX)
        err = merr(ENAMETOOLONG);
    else if (keybuf_sz != HSE_KVS_KLEN_MAX)
        err = merr(EINVAL);

    if (ev(err))
        return err;

    /* If valbuf is NULL and valbuf_sz is zero, this call is meant as a
     * probe for the existence of the key and length of its value. To
     * prevent c0/cn from allocating a new buffer for the value, set valbuf
     * to non-zero and proceed.
     */
    if (!valbuf && valbuf_sz == 0)
        valbuf = (void *)-1;

    kvs_ktuple_init(&kt, pfx, pfx_len);
    kvs_buf_init(&kbuf, keybuf, keybuf_sz);
    kvs_buf_init(&vbuf, valbuf, valbuf_sz);

    err = ikvdb_kvs_pfx_probe(handle, os, &kt, &res, &kbuf, &vbuf);
    if (ev(err))
        return err;

    sum = 0;

    switch (res) {
        case NOT_FOUND:
        case FOUND_PTMB:
        case FOUND_TMB:
            *found = HSE_KVS_PFX_FOUND_ZERO;
            break;

        case FOUND_VAL:
            *found = HSE_KVS_PFX_FOUND_ONE;
            *key_len = kbuf.b_len;
            *val_len = vbuf.b_len;
            sum = *key_len + *val_len;
            break;

        case FOUND_MULTIPLE:
            *found = HSE_KVS_PFX_FOUND_MUL;
            *key_len = kbuf.b_len;
            *val_len = vbuf.b_len;
            sum = *key_len + *val_len;
            break;
    }

    PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_PFXPROBE, PERFC_BA_KVDBOP_KVS_GETB, sum, 128);

    return 0UL;
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "hse_experimental_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
