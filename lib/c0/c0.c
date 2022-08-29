/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <stdint.h>

#include <urcu-bp.h>

#include <hse/util/platform.h>
#include <hse/error/merr.h>
#include <hse/util/event_counter.h>
#include <hse/util/alloc.h>
#include <hse/util/slab.h>
#include <hse/util/condvar.h>
#include <hse/logging/logging.h>

#define MTF_MOCK_IMPL_c0

#include <hse/ikvdb/ikvdb.h>
#include <hse/ikvdb/kvdb_health.h>
#include <hse/ikvdb/c0.h>
#include <hse/ikvdb/c0sk.h>
#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/c0_kvset.h>
#include <hse/ikvdb/c0_kvmultiset.h>

#include <kvdb/kvdb_keylock.h>

#include "c0_cursor.h"

struct rcu_head;
struct cursor_summary;

#define c0_h2r(handle) container_of(handle, struct c0_impl, c0_handle)

struct c0 {
};

/**
 * struct c0_impl - private representation of c0
 * @c0_handle:       opaque handle for users of a struct c0
 * @c0_c0sk:         handle to container poly C0, if within a poly C0
 * @c0_cn:           struct cn to ingest into
 * @c0_index:        index assigned to this C0
 * @c0_sfx_len:      suffix length for this c0
 * @c0_pfx_len:      prefix length for this c0
 * @c0_allow_writes: allow puts/dels
 */
struct c0_impl {
    struct c0    c0_handle;
    struct c0sk *c0_c0sk;
    struct cn   *c0_cn;
    uint32_t     c0_index;
    uint32_t     c0_sfx_len;
    int32_t      c0_pfx_len;
    bool         c0_allow_writes;
};

HSE_COLD merr_t
c0_init(size_t c0kvs_cache_sz, size_t c0kvs_cheap_sz)
{
    merr_t err;

    rcu_init();
    c0sk_init();
    c0kvs_init(c0kvs_cache_sz, c0kvs_cheap_sz);
    c0kvms_init();

    err = kvdb_ctxn_locks_init();
    if (err) {
        c0_fini();
        return err;
    }

    return 0;
}

HSE_COLD void
c0_fini(void)
{
    kvdb_ctxn_locks_fini();
    c0kvms_fini();
    c0kvs_fini();
    c0sk_fini();
}

int32_t
c0_get_pfx_len(struct c0 *handle)
{
    struct c0_impl *self = c0_h2r(handle);

    return self->c0_pfx_len;
}

merr_t
c0_put(struct c0 *handle, struct kvs_ktuple *kt, const struct kvs_vtuple *vt, uintptr_t seqnoref)
{
    struct c0_impl *self = c0_h2r(handle);

    assert(self->c0_index < HSE_KVS_COUNT_MAX);
    return c0sk_put(self->c0_c0sk, self->c0_index, kt, vt, seqnoref);
}

merr_t
c0_del(struct c0 *handle, struct kvs_ktuple *kt, uintptr_t seqnoref)
{
    struct c0_impl *self = c0_h2r(handle);

    assert(self->c0_index < HSE_KVS_COUNT_MAX);
    return c0sk_del(self->c0_c0sk, self->c0_index, kt, seqnoref);
}

merr_t
c0_prefix_del(struct c0 *handle, struct kvs_ktuple *kt, uintptr_t seqnoref)
{
    struct c0_impl *self = c0_h2r(handle);

    assert(self->c0_index < HSE_KVS_COUNT_MAX);
    return c0sk_prefix_del(self->c0_c0sk, self->c0_index, kt, seqnoref);
}

/*
 * Tombstone indicated by:
 *     return value == 0 && res == FOUND_TOMB
 */
merr_t
c0_get(
    struct c0 *              handle,
    const struct kvs_ktuple *kt,
    uint64_t                 view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf)
{
    struct c0_impl *self;

    self = c0_h2r(handle);

    assert(self->c0_index < HSE_KVS_COUNT_MAX);
    return c0sk_get(
        self->c0_c0sk, self->c0_index, self->c0_pfx_len, kt, view_seqno, seqnoref, res, vbuf);
}

merr_t
c0_pfx_probe(
    struct c0 *              handle,
    const struct kvs_ktuple *kt,
    uint64_t                 view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct query_ctx *       qctx,
    struct kvs_buf *         kbuf,
    struct kvs_buf *         vbuf)
{
    struct c0_impl *self;

    self = c0_h2r(handle);

    assert(self->c0_index < HSE_KVS_COUNT_MAX);
    return c0sk_pfx_probe(
        self->c0_c0sk,
        self->c0_index,
        self->c0_pfx_len,
        self->c0_sfx_len,
        kt,
        view_seqno,
        seqnoref,
        res,
        qctx,
        kbuf,
        vbuf);
}

merr_t
c0_open(struct ikvdb *kvdb, struct cn *cn, struct c0 **c0)
{
    struct kvs_cparams *cp = cn_get_cparams(cn);
    struct kvs_rparams *rp = cn_get_rp(cn);
    struct c0_impl *new_c0;
    merr_t err;
    uint16_t skidx;

    new_c0 = calloc(1, sizeof(*new_c0));
    if (!new_c0) {
        err = merr(ENOMEM);
        log_errx("Allocation failed for struct c0", err);
        return err;
    }

    assert(cn);
    new_c0->c0_pfx_len = cp->pfx_len;
    new_c0->c0_sfx_len = rp->kvs_sfxlen;
    new_c0->c0_cn = cn;
    new_c0->c0_allow_writes = ikvdb_allows_user_writes(kvdb);

    ikvdb_get_c0sk(kvdb, &new_c0->c0_c0sk);
    if (ev(!new_c0->c0_c0sk)) {
        free(new_c0);
        return merr(EINVAL);
    }

    err = c0sk_c0_register(new_c0->c0_c0sk, new_c0->c0_cn, &skidx);
    if (ev(err)) {
        log_errx("c0sk_c0_register failed", err);
        free(new_c0);
        return err;
    }

    new_c0->c0_index = skidx;
    *c0 = &new_c0->c0_handle;

    return 0;
}

merr_t
c0_close(struct c0 *handle)
{
    merr_t          err = 0, tmp_err;
    struct c0_impl *self;

    if (!handle)
        return merr(ev(EINVAL));

    self = c0_h2r(handle);

    tmp_err = c0_sync(handle);

    if (ev(tmp_err))
        err = tmp_err;

    tmp_err = c0sk_c0_deregister(self->c0_c0sk, self->c0_index);
    if (!err && ev(tmp_err))
        err = tmp_err;

    free(self);

    return err;
}

merr_t
c0_cursor_create(
    struct c0 *            handle,
    uint64_t               seqno,
    bool                   reverse,
    const void *           prefix,
    size_t                 pfx_len,
    struct cursor_summary *summary,
    struct c0_cursor **    c0cur)
{
    struct c0_impl *self = c0_h2r(handle);
    merr_t          err;

    err = c0sk_cursor_create(
        self->c0_c0sk,
        seqno,
        self->c0_index,
        reverse,
        self->c0_pfx_len,
        prefix,
        pfx_len,
        summary,
        c0cur);
    return ev(err);
}

void
c0_cursor_bind_txn(struct c0_cursor *c0cur, struct kvdb_ctxn *ctxn)
{
    c0sk_cursor_bind_txn(c0cur, ctxn);
}

merr_t
c0_cursor_seek(struct c0_cursor *c0cur, const void *seek, size_t seeklen, struct kc_filter *filter)
{
    merr_t err;

    err = c0sk_cursor_seek(c0cur, seek, seeklen, filter);
    return ev(err);
}

merr_t
c0_cursor_read(struct c0_cursor *c0cur, struct kvs_cursor_element *elem, bool *eof)
{
    merr_t err;

    err = c0sk_cursor_read(c0cur, elem, eof);
    return ev(err);
}

static bool
c0cur_next(struct element_source *es, void **element)
{
    struct c0_cursor *c0cur = container_of(es, struct c0_cursor, c0cur_es);
    bool              eof;
    merr_t            err;

    err = c0_cursor_read(c0cur, &c0cur->c0cur_elem, &eof);
    if (ev(err) || eof)
        return false;

    c0cur->c0cur_elem.kce_source = KCE_SOURCE_C0;
    *element = &c0cur->c0cur_elem;
    return true;
}

struct element_source *
c0_cursor_es_make(struct c0_cursor *c0cur)
{
    c0cur->c0cur_es = es_make(c0cur_next, 0, 0);
    return &c0cur->c0cur_es;
}

struct element_source *
c0_cursor_es_get(struct c0_cursor *c0cur)
{
    return &c0cur->c0cur_es;
}

merr_t
c0_cursor_update(struct c0_cursor *c0cur, uint64_t seqno, uint32_t *flags_out)
{
    return c0sk_cursor_update(c0cur, seqno, flags_out);
}

merr_t
c0_cursor_destroy(struct c0_cursor *c0cur)
{
    merr_t err;

    err = c0sk_cursor_destroy(c0cur);
    return ev(err);
}

/* Sync only forces all current data to media -- it does not
 * prevent new data from being created while the sync blocks.
 */
merr_t
c0_sync(struct c0 *handle)
{
    struct c0_impl *self = c0_h2r(handle);

    if (!self->c0_allow_writes)
        return 0;

    return c0sk_sync(self->c0_c0sk, HSE_KVDB_SYNC_REFWAIT);
}

uint16_t
c0_index(struct c0 *handle)
{
    struct c0_impl *self = c0_h2r(handle);

    return self->c0_index;
}

#if HSE_MOCKING
#include "c0_ut_impl.i"
#endif /* HSE_MOCKING */
