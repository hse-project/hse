/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/conditions.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/keycmp.h>
#include <hse_util/table.h>
#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/cn_cursor.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>

#include "../kvdb/kvdb_log.h"
#include "../../cn/test/mock_kvset_builder.h"

#include <stdlib.h>

/* ------------------------------------------------------------
 * Mocked c0/cn
 *
 * This mock allows coverage testing of kvs, ikvdb, kvdb.
 *
 * It presents a simulated c0/cn pair that can hold up to 10 keys+vals
 * of 10 bytes each.  It simulates media full after 10 keys by failing
 * c0_put.  The full put/get/del/scan interface is covered.
 *
 * It is a bare-bones mock that does not cover tombstones, data
 * migration into cn, sequences, snapshots, etc.  Support for these
 * should be added as need arises.
 */

struct cn;
struct mpool;
struct c0;

#define KEY_LEN 10
#define VAL_LEN 10
#define KEY_CNT 10

struct c0_data {
    int  klen;
    int  vlen;
    char key[KEY_LEN];
    char val[KEY_LEN];
};

struct mock_cn {
    char            tripwire[PAGE_SIZE * 3];
    struct c0_data *data;
    struct cndb *   cndb;
    atomic_t        refcnt;
} __aligned(PAGE_SIZE);

struct mock_c0 {
    char           tripwire[PAGE_SIZE * 3];
    struct c0_data data[KEY_CNT];
    u64            hash;
    u32            index;
} __aligned(PAGE_SIZE);

struct c0_cursor {
    char tripwire[PAGE_SIZE * 3];
    int  junk;
};

struct cn_cursor {
    char            tripwire[PAGE_SIZE * 3];
    char            prefix[KEY_LEN];
    struct c0_data *data;
    u64             seqno;
    int             pfx_len;
    int             i;
    bool            eof;
};

static atomic_t _c0_open_cnt;

/*
 * c0_open receives the mock cn in its arguments.
 * mock_c0 and mock_cn share the underlying data structure;
 * so this code must establish the link.
 */
static merr_t
_c0_open(struct ikvdb *kvdb, struct kvs_rparams *rp, struct cn *cn, struct mpool *ds, struct c0 **h)
{
    struct mock_cn *mn = (void *)cn;
    struct mock_c0 *m0;

    m0 = mmap(NULL, sizeof(*m0), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (m0 == MAP_FAILED)
        return merr(ENOMEM);

    memset(m0->tripwire, 0xaa, sizeof(m0->tripwire));

    /* Make the tripwire pages inaccessible to catch errant
     * unmocked accesses dead in their tracks.
     */
    if (mprotect(m0, sizeof(m0->tripwire), PROT_NONE))
        return merr(errno);

    m0->index = atomic_inc_return(&_c0_open_cnt);
    m0->hash = (uintptr_t)m0;

    if (mn) {
        m0->hash = cn_hash_get(cn);
        mn->data = m0->data; /* inform mock_cn of the data */
    }

    *h = (struct c0 *)m0;

    return 0;
}

static merr_t
_c0_close(struct c0 *h)
{
    struct mock_c0 *c0 = (void *)h;

    if (munmap(c0, sizeof(c0)))
        return merr(errno);

    return 0;
}

static u16
_c0_index(struct c0 *handle)
{
    struct mock_c0 *m0 = (void *)handle;

    return m0 ? m0->index : U16_MAX;
}

static u64
_c0_hash_get(struct c0 *handle)
{
    struct mock_c0 *m0 = (void *)handle;

    return m0 ? m0->hash : -1;
}

static merr_t
_c0_cursor_create(
    struct c0 *            handle,
    u64                    seqno,
    bool                   reverse,
    const void *           prefix,
    size_t                 pfx_len,
    struct cursor_summary *summary,
    struct c0_cursor **    c0cur)
{
    struct c0_cursor *cur;

    cur = mmap(NULL, sizeof(*cur), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (cur == MAP_FAILED)
        return merr(ENOMEM);

    memset(cur->tripwire, 0xaa, sizeof(cur->tripwire));

    /* Make the tripwire pages inaccessible to catch errant
     * unmocked accesses dead in their tracks.
     */
    if (mprotect(cur, sizeof(cur->tripwire), PROT_NONE))
        return merr(errno);

    *c0cur = (void *)cur;

    return 0;
}

static merr_t
_c0_cursor_update(
    struct c0_cursor *       cur,
    u64                      seqno,
    const struct kvs_ktuple *kmin,
    const struct kvs_ktuple *kmax,
    u32 *                    flags)
{
    return 0;
}

static merr_t
_c0_cursor_bind_txn(struct c0_cursor *cur, struct kvdb_ctxn *txn)
{
    return 0;
}

static merr_t
_c0_cursor_save(struct c0_cursor *cur)
{
    return 0;
}

static merr_t
_c0_cursor_restore(struct c0_cursor *cur)
{
    return 0;
}

static merr_t
_c0_cursor_destroy(struct c0_cursor *cur)
{
    munmap(cur, sizeof(*cur));

    return 0;
}

static merr_t
_c0_cursor_read(struct c0_cursor *cur, struct kvs_kvtuple *kvt, bool *eof)
{
    *eof = true;
    return 0;
}

static merr_t
_c0_cursor_seek(
    struct c0_cursor * cur,
    const void *       prefix,
    size_t             pfx_len,
    struct kc_filter * filter,
    struct kvs_ktuple *kt)
{
    if (kt)
        kt->kt_len = 0;
    return 0;
}

static merr_t
_c0_put(
    struct c0 *              handle,
    const struct kvs_ktuple *kt,
    const struct kvs_vtuple *vt,
    const uintptr_t          seqno)
{
    struct mock_c0 *m0 = (void *)handle;
    int             i;

    if (kt->kt_len > KEY_LEN || vt->vt_len > VAL_LEN)
        return merr(ev(EINVAL));

    for (i = 0; i < KEY_CNT; ++i) {
        if (m0->data[i].klen == 0) {
            memcpy(&m0->data[i].key, kt->kt_data, kt->kt_len);
            memcpy(&m0->data[i].val, vt->vt_data, vt->vt_len);
            m0->data[i].klen = kt->kt_len;
            m0->data[i].vlen = vt->vt_len;
            return 0;
        }
    }

    return merr(ev(ENOSPC));
}

static merr_t
_c0_get(
    struct c0 *              handle,
    const struct kvs_ktuple *kt,
    u64                      view_seqno,
    uintptr_t                seqnoref,
    enum key_lookup_res *    res,
    struct kvs_buf *         vbuf)
{
    struct mock_c0 *m0 = (void *)handle;
    int             i;

    if (kt->kt_len > KEY_LEN || vbuf->b_buf_sz > VAL_LEN)
        return merr(ev(EINVAL));

    for (i = 0; i < KEY_CNT; ++i) {
        if (m0->data[i].klen && memcmp(m0->data[i].key, kt->kt_data, kt->kt_len) == 0) {
            u32 copylen;

            vbuf->b_len = m0->data[i].vlen;

            copylen = MIN(vbuf->b_len, vbuf->b_buf_sz);
            memcpy(vbuf->b_buf, m0->data[i].val, copylen);
            *res = FOUND_VAL;
            return 0;
        }
    }

    *res = NOT_FOUND;
    return 0;
}

static merr_t
_cn_get(
    struct cn *          handle,
    struct kvs_ktuple *  kt,
    u64                  seq,
    enum key_lookup_res *res,
    struct kvs_buf *     vbuf)
{
    *res = NOT_FOUND;
    return 0;
}

static merr_t
_c0_del(struct c0 *handle, struct kvs_ktuple *kt, const uintptr_t seqno)
{
    struct mock_c0 *m0 = (void *)handle;
    int             i;

    if (kt->kt_len > KEY_LEN)
        return merr(ev(EINVAL));

    for (i = 0; i < KEY_CNT; ++i) {
        if (m0->data[i].klen && memcmp(m0->data[i].key, kt->kt_data, kt->kt_len) == 0) {
            m0->data[i].klen = 0;
            return 0;
        }
    }

    return 0;
}

static merr_t
_cn_open(
    struct cn_kvdb *    cn_kvdb,
    struct mpool *      ds,
    struct kvdb_kvs *   kvs,
    struct cndb *       cndb,
    u64                 cnid,
    struct kvs_rparams *rp,
    const char *        mp_name,
    const char *        kvs_name,
    struct kvdb_health *health,
    uint                flags,
    struct cn **        out)
{
    /* CN is called first, then c0_open is called with returned handle */
    struct mock_cn *cn;

    cn = mmap(NULL, sizeof(*cn), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (cn == MAP_FAILED)
        return merr(ENOMEM);

    memset(cn->tripwire, 0xaa, sizeof(cn->tripwire));

    /* Make the tripwire pages inaccessible to catch errant
     * unmocked accesses dead in their tracks.
     */
    if (mprotect(cn, sizeof(cn->tripwire), PROT_NONE))
        return merr(errno);

    cn->cndb = cndb;
    *out = (void *)cn;

    return 0;
}

static merr_t
_cn_close(struct cn *h)
{
    struct mock_cn *cn = (void *)h;

    if (munmap(cn, sizeof(*cn)))
        return merr(errno);

    return 0;
}

static void
_cn_ref_get(struct cn *arg)
{
    struct mock_cn *cn = (struct mock_cn *)arg;

    atomic_inc(&cn->refcnt);
}

static void
_cn_ref_put(struct cn *arg)
{
    struct mock_cn *cn = (struct mock_cn *)arg;

    atomic_dec(&cn->refcnt);
}

static u64
_cn_hash_get(const struct cn *arg)
{
    return (uintptr_t)arg;
}

static struct perfc_set *
_cn_get_ingest_perfc(const struct cn *cn)
{
    return NULL;
}

static void
_cn_disable_maint(struct cn *cn, bool onoff)
{
}

static int
cmp(const void *a_, const void *b_)
{
    const struct c0_data *a = a_;
    const struct c0_data *b = b_;

    return keycmp(a->key, a->klen, b->key, b->klen);
}

static merr_t
_cn_cursor_create(
    struct cn *            cn,
    u64                    seqno,
    bool                   reverse,
    const void *           prefix,
    u32                    pfx_len,
    struct cursor_summary *summary,
    void **                cursorp)
{
    struct mock_cn *  mn = (void *)cn;
    struct cn_cursor *cur;

    cur = mmap(NULL, sizeof(*cur), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
    if (cur == MAP_FAILED)
        return merr(ENOMEM);

    memset(cur->tripwire, 0xaa, sizeof(cur->tripwire));

    /* Make the tripwire pages inaccessible to catch errant
     * unmocked accesses dead in their tracks.
     */
    if (mprotect(cur, sizeof(cur->tripwire), PROT_NONE))
        return merr(errno);

    memcpy(cur->prefix, prefix, pfx_len);
    cur->pfx_len = pfx_len;
    cur->seqno = seqno;
    cur->i = 0;
    cur->data = mn->data;

    if (mn->data)
        qsort(mn->data, KEY_CNT, sizeof(struct c0_data), cmp);
    else
        cur->i = KEY_CNT;

    *cursorp = cur;

    return 0;
}

static merr_t
_cn_cursor_update(void *handle, u64 seqno, bool *updated)
{
    struct cn_cursor *cur = handle;

    if (updated)
        *updated = false;

    cur->seqno = seqno;
    return 0;
}

static merr_t
_cn_cursor_read(void *handle, struct kvs_kvtuple *kvt, bool *eof)
{
    struct cn_cursor *cur = handle;

    while (cur->i < KEY_CNT) {
        struct c0_data *d = &cur->data[cur->i];

        ++cur->i;
        if (d->klen) {
            if (cur->pfx_len && memcmp(d->key, cur->prefix, cur->pfx_len))
                continue;

            kvt->kvt_key.kt_data = d->key;
            kvt->kvt_key.kt_len = d->klen;
            kvt->kvt_value.vt_data = d->val;
            kvt->kvt_value.vt_len = d->vlen;
            *eof = false;

            return 0;
        }
    }

    *eof = true;
    return 0;
}

static merr_t
_cn_cursor_seek(
    void *             cursor,
    const void *       key,
    u32                len,
    struct kc_filter * filter,
    struct kvs_ktuple *kt)
{
    struct cn_cursor *cur = (struct cn_cursor *)cursor;

    if (!cur->data)
        goto missed;

    for (cur->i = 0; cur->i < KEY_CNT; ++cur->i) {
        struct c0_data *d = &cur->data[cur->i];

        if (keycmp(key, len, d->key, d->klen) <= 0) {
            if (kt) {
                kt->kt_data = d->key;
                kt->kt_len = d->klen;
            }
            return 0;
        }
    }

missed:
    if (kt)
        kt->kt_len = 0;

    return 0;
}

static void
_cn_cursor_destroy(void *cur)
{
    munmap(cur, sizeof(struct cn_cursor));
}

merr_t
_cn_cursor_active_kvsets(void *cursor, u32 *active, u32 *total)
{
    *active = 0;
    *total = 0;

    return 0;
}

static merr_t
_kvdb_log_replay(
    struct kvdb_log *log,
    u64 *            cndblog_oid1,
    u64 *            cndblog_oid2,
    u64 *            c1_oid1,
    u64 *            c1_oid2)
{
    return 0;
}

static u64 _cndb_id;

static merr_t
_cndb_alloc(struct mpool *ds, u64 *captgt, u64 *oid1, u64 *oid2)
{
    *oid1 = ++_cndb_id;
    *oid2 = ++_cndb_id;
    return 0;
}

static merr_t
_cndb_make(struct mpool *ds, u64 captgt, u64 oid1, u64 oid2)
{
    return 0;
}

static merr_t
_cndb_cn_make(struct cndb *cndb, struct kvs_cparams *cp, u64 *cnid, char *name)
{
    *cnid = ++_cndb_id;
    return 0;
}

struct kvs_cparams cp;

void
mock_cn_set()
{
    mapi_inject(mapi_idx_cn_make, 0);
    mapi_inject(mapi_idx_cn_ingestv, 0);
    mapi_inject(mapi_idx_cn_get_sfx_len, 0);
    mapi_inject(mapi_idx_cn_periodic, 0);

    cp.cp_fanout = 8;
    mapi_inject_ptr(mapi_idx_cn_get_cparams, &cp);

    mock_kvset_builder_set();

    MOCK_SET(cn, _cn_open);
    MOCK_SET(cn, _cn_close);
    MOCK_SET(cn, _cn_get);
    MOCK_SET(cn, _cn_ref_get);
    MOCK_SET(cn, _cn_ref_put);
    MOCK_SET(cn, _cn_hash_get);
    MOCK_SET(cn, _cn_get_ingest_perfc);
    MOCK_SET(cn, _cn_disable_maint);

    MOCK_SET(cn_cursor, _cn_cursor_create);
    MOCK_SET(cn_cursor, _cn_cursor_update);
    MOCK_SET(cn_cursor, _cn_cursor_read);
    MOCK_SET(cn_cursor, _cn_cursor_seek);
    MOCK_SET(cn_cursor, _cn_cursor_destroy);
    MOCK_SET(cn_cursor, _cn_cursor_active_kvsets);
}

void
mock_cn_unset()
{
    mapi_inject_unset(mapi_idx_cn_make);
    mapi_inject_unset(mapi_idx_cn_ingestv);
    mapi_inject_unset(mapi_idx_cn_get_sfx_len);
    mapi_inject_unset(mapi_idx_cn_periodic);

    mock_kvset_builder_unset();

    MOCK_UNSET(cn, _cn_open);
    MOCK_UNSET(cn, _cn_close);
    MOCK_UNSET(cn, _cn_get);
    MOCK_UNSET(cn, _cn_ref_get);
    MOCK_UNSET(cn, _cn_ref_put);
    MOCK_UNSET(cn, _cn_hash_get);
    MOCK_UNSET(cn, _cn_get_ingest_perfc);
    MOCK_UNSET(cn, _cn_disable_maint);

    MOCK_UNSET(cn_cursor, _cn_cursor_create);
    MOCK_UNSET(cn_cursor, _cn_cursor_update);
    MOCK_UNSET(cn_cursor, _cn_cursor_read);
    MOCK_UNSET(cn_cursor, _cn_cursor_seek);
    MOCK_UNSET(cn_cursor, _cn_cursor_destroy);
    MOCK_UNSET(cn_cursor, _cn_cursor_active_kvsets);
}

void
mock_c0_set()
{
    MOCK_SET(c0, _c0_open);
    MOCK_SET(c0, _c0_close);
    MOCK_SET(c0, _c0_index);
    MOCK_SET(c0, _c0_hash_get);
    MOCK_SET(c0, _c0_put);
    MOCK_SET(c0, _c0_get);
    MOCK_SET(c0, _c0_del);
    MOCK_SET(c0, _c0_cursor_create);
    MOCK_SET(c0, _c0_cursor_update);
    MOCK_SET(c0, _c0_cursor_bind_txn);
    MOCK_SET(c0, _c0_cursor_read);
    MOCK_SET(c0, _c0_cursor_seek);
    MOCK_SET(c0, _c0_cursor_save);
    MOCK_SET(c0, _c0_cursor_restore);
    MOCK_SET(c0, _c0_cursor_destroy);
}

void
mock_c0_unset()
{
    MOCK_UNSET(c0, _c0_open);
    MOCK_UNSET(c0, _c0_close);
    MOCK_UNSET(c0, _c0_index);
    MOCK_UNSET(c0, _c0_hash_get);
    MOCK_UNSET(c0, _c0_put);
    MOCK_UNSET(c0, _c0_get);
    MOCK_UNSET(c0, _c0_del);
    MOCK_UNSET(c0, _c0_cursor_create);
    MOCK_UNSET(c0, _c0_cursor_update);
    MOCK_UNSET(c0, _c0_cursor_bind_txn);
    MOCK_UNSET(c0, _c0_cursor_seek);
    MOCK_UNSET(c0, _c0_cursor_read);
    MOCK_UNSET(c0, _c0_cursor_save);
    MOCK_UNSET(c0, _c0_cursor_restore);
    MOCK_UNSET(c0, _c0_cursor_destroy);
}

void
mock_c0cn_set()
{
    mock_cn_set();
    mock_c0_set();
}

void
mock_c0cn_unset()
{
    mock_cn_unset();
    mock_c0_unset();
}

void
mock_kvdb_log_set()
{
    mapi_inject(mapi_idx_kvdb_log_make, 0);
    mapi_inject(mapi_idx_kvdb_log_open, 0);
    mapi_inject(mapi_idx_kvdb_log_close, 0);
    mapi_inject(mapi_idx_kvdb_log_rollover, 0);
    mapi_inject(mapi_idx_kvdb_log_done, 0);
    mapi_inject(mapi_idx_kvdb_log_abort, 0);
    mapi_inject(mapi_idx_kvdb_log_mdc_create, 0);

#if 0
    mapi_inject(mapi_idx_mpool_mdc_open, 0);
    mapi_inject(mapi_idx_mpool_mdc_close, 0);
#endif
    mapi_inject(mapi_idx_cndb_make, 0);
    mapi_inject(mapi_idx_cndb_replay, 0);

    mapi_inject_unset(mapi_idx_kvdb_log_replay);
    MOCK_SET(kvdb_log, _kvdb_log_replay);
}

void
mock_kvdb_log_unset()
{
    mapi_inject_unset(mapi_idx_kvdb_log_make);
    mapi_inject_unset(mapi_idx_kvdb_log_open);
    mapi_inject_unset(mapi_idx_kvdb_log_close);
    mapi_inject_unset(mapi_idx_kvdb_log_rollover);
    mapi_inject_unset(mapi_idx_kvdb_log_done);
    mapi_inject_unset(mapi_idx_kvdb_log_abort);
    mapi_inject_unset(mapi_idx_kvdb_log_mdc_create);

#if 0
    mapi_inject_unset(mapi_idx_mpool_mdc_open);
    mapi_inject_unset(mapi_idx_mpool_mdc_close);
#endif
    mapi_inject_unset(mapi_idx_cndb_make);
    mapi_inject_unset(mapi_idx_cndb_replay);

    MOCK_UNSET(kvdb_log, _kvdb_log_replay);
}

void
mock_cndb_set()
{
    mapi_inject(mapi_idx_cndb_cnv_get, 0);
    mapi_inject(mapi_idx_cndb_cn_info_idx, 0);
    mapi_inject(mapi_idx_cndb_cn_count, 0);
    mapi_inject(mapi_idx_cndb_open, 0);
    mapi_inject(mapi_idx_cndb_close, 0);
    mapi_inject(mapi_idx_cndb_replay, 0);

    mapi_inject(mapi_idx_cndb_txn_start, 0);
    mapi_inject(mapi_idx_cndb_txn_txc, 0);
    mapi_inject(mapi_idx_cndb_txn_txd, 0);
    mapi_inject(mapi_idx_cndb_txn_meta, 0);
    mapi_inject(mapi_idx_cndb_txn_ack_c, 0);
    mapi_inject(mapi_idx_cndb_txn_ack_d, 0);
    mapi_inject(mapi_idx_cndb_txn_nak, 0);

    MOCK_SET(cndb, _cndb_alloc);
    MOCK_SET(cndb, _cndb_make);
    MOCK_SET(cndb, _cndb_cn_make);
}

void
mock_cndb_unset()
{
    mapi_inject_unset(mapi_idx_cndb_cnv_get);
    mapi_inject_unset(mapi_idx_cndb_cn_info_idx);
    mapi_inject_unset(mapi_idx_cndb_cn_count);
    mapi_inject_unset(mapi_idx_cndb_open);
    mapi_inject_unset(mapi_idx_cndb_close);
    mapi_inject_unset(mapi_idx_cndb_replay);

    mapi_inject_unset(mapi_idx_cndb_txn_start);
    mapi_inject_unset(mapi_idx_cndb_txn_txc);
    mapi_inject_unset(mapi_idx_cndb_txn_txd);
    mapi_inject_unset(mapi_idx_cndb_txn_meta);
    mapi_inject_unset(mapi_idx_cndb_txn_ack_c);
    mapi_inject_unset(mapi_idx_cndb_txn_ack_d);
    mapi_inject_unset(mapi_idx_cndb_txn_nak);

    MOCK_UNSET(cndb, _cndb_alloc);
    MOCK_UNSET(cndb, _cndb_make);
    MOCK_UNSET(cndb, _cndb_cn_make);
}
