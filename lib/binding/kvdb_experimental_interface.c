/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/hse.h>
#include <hse/types.h>
#include <hse/flags.h>

#include <hse_util/platform.h>
#include <hse_util/logging.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/kvdb_perfc.h>
#include <hse_ikvdb/config.h>

uint64_t
hse_kvs_prefix_probe(
    struct hse_kvs *            handle,
    const unsigned int          flags,
    struct hse_kvdb_txn *const  txn,
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
    u64 sum             HSE_MAYBE_UNUSED;

    if (!handle || !pfx || !pfx_len || !found || !val_len || flags != 0)
        err = merr(EINVAL);
    else if (!valbuf && valbuf_sz > 0)
        err = merr(EINVAL);
    else if (pfx_len > HSE_KVS_KEY_LEN_MAX)
        err = merr(ENAMETOOLONG);
    else if (keybuf_sz != HSE_KVS_KEY_LEN_MAX)
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

    err = ikvdb_kvs_pfx_probe(handle, flags, txn, &kt, &res, &kbuf, &vbuf);
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

    PERFC_INCADD_RU(&kvdb_pc, PERFC_RA_KVDBOP_KVS_PFXPROBE, PERFC_RA_KVDBOP_KVS_GETB, sum);

    return 0UL;
}
