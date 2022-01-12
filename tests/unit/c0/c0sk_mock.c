/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ikvdb/c0sk.h>
#include <support/random_buffer.h>

#include <hse_util/platform.h>

#include "c0sk_mock.h"

merr_t
_c0sk_open(
    struct kvdb_rparams *kvdb_rp,
    struct mpool *       mp_dataset,
    const char *         mp_name,
    struct kvdb_health * health,
    atomic_ulong        *kvdb_seq,
    u64                  gen,
    struct c0sk **       c0sk)
{
    return 0;
}

merr_t
_c0sk_close(struct c0sk *self)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);

    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
_c0sk_c0_register(struct c0sk *self, struct cn *cn, u16 *skidx)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    *skidx = mock_c0sk->mczk_skidx;
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
_c0sk_c0_deregister(struct c0sk *self, u16 skidx)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
_c0sk_put(
    struct c0sk *            self,
    u16                      skidx,
    struct kvs_ktuple       *key,
    const struct kvs_vtuple *value,
    const uintptr_t          seqno)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
_c0sk_get(
    struct c0sk *            self,
    u16                      skidx,
    u32                      pfx_len,
    const struct kvs_ktuple *key,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
_c0sk_del(struct c0sk *self, u16 skidx, struct kvs_ktuple *key, const uintptr_t seqno)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
_c0sk_prefix_del(struct c0sk *self, u16 skidx, struct kvs_ktuple *key, const uintptr_t seqno)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

struct c0_kvmultiset;

merr_t
_c0sk_sync(struct c0sk *self, unsigned int flags)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)self;
    merr_t            err = 0;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    if (mock_c0sk->mczk_err) {
        err = merr(mock_c0sk->mczk_err);
        mock_c0sk->mczk_err = 0;
    }

    return err;
}

merr_t
create_mock_c0sk(struct c0sk **c0sk)
{
    struct mock_c0sk *mock_c0sk;

    mock_c0sk = calloc(1, sizeof(struct mock_c0sk));
    if (!mock_c0sk)
        return merr(ENOMEM);

    MOCK_SET(c0sk, _c0sk_open);
    MOCK_SET(c0sk, _c0sk_close);
    MOCK_SET(c0sk, _c0sk_c0_register);
    MOCK_SET(c0sk, _c0sk_c0_deregister);
    MOCK_SET(c0sk, _c0sk_put);
    MOCK_SET(c0sk, _c0sk_get);
    MOCK_SET(c0sk, _c0sk_del);
    MOCK_SET(c0sk, _c0sk_prefix_del);
    MOCK_SET(c0sk, _c0sk_sync);

    mock_c0sk->mczk_integrity = INTEGRITY_CHECK;

    *c0sk = (struct c0sk *)mock_c0sk;

    return 0;
}

void
destroy_mock_c0sk(struct c0sk *c0sk)
{
    struct mock_c0sk *mock_c0sk = (struct mock_c0sk *)c0sk;

    assert(mock_c0sk->mczk_integrity == INTEGRITY_CHECK);
    free(mock_c0sk);
}
