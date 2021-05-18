/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include "framework_external.h"

#include <hse_ut/conditions.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/keycmp.h>
#include <hse_util/table.h>
#include <hse_util/spinlock.h>

#include <hse_ikvdb/kvs.h>
#include <hse_ikvdb/cn.h>
#include <cn/cn_cursor.h>
#include <hse_ikvdb/c0.h>
#include <hse_ikvdb/cndb.h>
#include <hse_ikvdb/kvdb_health.h>

#include <kvdb/kvdb_log.h>
#include <mocks/mock_kvset_builder.h>

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

#define KEY_LEN 20
#define VAL_LEN 20
#define KEY_CNT 5200

struct c0_data {
    int  klen;
    u64  xlen;
    char key[KEY_LEN];
    char val[KEY_LEN];
};

static inline uint
c0_data_vlen(struct c0_data *d)
{
    return d->xlen & 0xfffffffful;
}

struct c0 {
};

#define mock_c0_h2r(h) container_of(h, struct mock_c0, handle)

struct mock_c0;
struct mock_cn;

struct mock_c0_cursor {
    char tripwire[PAGE_SIZE * 7]; /* must be first field */
    struct mock_c0 *c0;
    struct element_source c0cur_es;
    struct kvs_cursor_element c0cur_elem;
    void *cc_next;
};

struct mock_c0 {
    char            tripwire[PAGE_SIZE * 7]; /* must be first field */
    struct c0       handle;
    struct c0_data  data[KEY_CNT];
    struct c0sk    *c0_c0sk;
    u64             hash;
    u32             index;

    spinlock_t             cc_lock;
    struct mock_c0_cursor *cc_head;
};

struct mock_cn_cursor {
    char            tripwire[PAGE_SIZE * 7]; /* must be first field! */
    char            prefix[KEY_LEN];
    struct element_source es;
    struct kvs_cursor_element elem;
    struct c0_data *data;
    u64             seqno;
    int             pfx_len;
    int             i;
    bool            eof;
    struct mock_cn *cn;
    void           *cc_next;
};

struct mock_cn {
    char            tripwire[PAGE_SIZE * 7]; /* must be first field */
    struct c0_data *data;
    struct cndb *   cndb;
    atomic_t        refcnt;

    spinlock_t             cc_lock;
    struct mock_cn_cursor *cc_head;
} HSE_ALIGNED(PAGE_SIZE);

static atomic_t mocked_c0_open_count;
static struct kvs_rparams mocked_kvs_rparams;
static struct kvs_cparams mocked_kvs_cparams;


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
    if (mprotect(m0->tripwire, sizeof(m0->tripwire), PROT_NONE))
        return merr(errno);

    m0->index = atomic_inc_return(&mocked_c0_open_count);
    m0->hash = (uintptr_t)m0;

    if (mn) {
        m0->hash = cn_hash_get(cn);
        mn->data = m0->data; /* inform mock_cn of the data */
    }

    spin_lock_init(&m0->cc_lock);
    m0->cc_head = NULL;

    *h = &m0->handle;

    return 0;
}

static merr_t
_c0_close(struct c0 *h)
{
    struct mock_c0 *c0 = mock_c0_h2r(h);
    struct mock_c0_cursor *cur;

    while ((cur = c0->cc_head)) {
        c0->cc_head = cur->cc_next;
        munmap(cur, sizeof(*cur));
    }

    if (munmap(c0, sizeof(c0)))
        return merr(errno);

    return 0;
}

static u16
_c0_index(struct c0 *handle)
{
    struct mock_c0 *m0 = mock_c0_h2r(handle);

    return m0 ? m0->index : HSE_KVS_COUNT_MAX - 1;
}

static u64
_c0_hash_get(struct c0 *handle)
{
    struct mock_c0 *m0 = mock_c0_h2r(handle);

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
    struct mock_c0 *c0 = mock_c0_h2r(handle);
    struct mock_c0_cursor *cur;

    spin_lock(&c0->cc_lock);
    cur = c0->cc_head;
    if (cur)
        c0->cc_head = cur->cc_next;
    spin_unlock(&c0->cc_lock);

    if (!cur) {
        cur = mmap(NULL, sizeof(*cur), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (cur == MAP_FAILED)
            return merr(ENOMEM);

        memset(cur->tripwire, 0xaa, sizeof(cur->tripwire));

        /* Make the tripwire pages inaccessible to catch errant
         * unmocked accesses dead in their tracks.
         */
        if (mprotect(cur->tripwire, sizeof(cur->tripwire), PROT_NONE))
            return merr(errno);
    }

    cur->c0 = c0;
    *c0cur = (void *)cur;

    return 0;
}

static merr_t
_c0_cursor_destroy(struct c0_cursor *arg)
{
    struct mock_c0_cursor *cur = (void *)arg;
    struct mock_c0 *c0 = cur->c0;

    spin_lock(&c0->cc_lock);
    cur->cc_next = c0->cc_head;
    c0->cc_head = cur;
    spin_unlock(&c0->cc_lock);

    return 0;
}

static merr_t
_c0_cursor_read(struct c0_cursor *cur, struct kvs_cursor_element *elem, bool *eof)
{
    *eof = true;
    return 0;
}

static merr_t
_c0_cursor_seek(
    struct c0_cursor * cur,
    const void *       prefix,
    size_t             pfx_len,
    struct kc_filter * filter)
{
    return 0;
}

/* Make sure this is in sync with the function in c0.c */
static bool
c0cur_next(struct element_source *es, void **element) {
    struct mock_c0_cursor *c0cur = container_of(es, struct mock_c0_cursor, c0cur_es);
    bool eof;
    merr_t err;

    err = _c0_cursor_read((void *)c0cur, &c0cur->c0cur_elem, &eof);
    if (ev(err) || eof)
        return false;

    c0cur->c0cur_elem.kce_source = KCE_SOURCE_C0;
    *element = &c0cur->c0cur_elem;
    return true;
}

struct element_source *
_c0_cursor_es_make(
    struct c0_cursor * c0cur)
{
    struct mock_c0_cursor *cur = (void *)c0cur;

	cur->c0cur_es = es_make(c0cur_next, 0, 0);
    return &cur->c0cur_es;
}

struct element_source *
_c0_cursor_es_get(
    struct c0_cursor * c0cur)
{
    struct mock_c0_cursor *cur = (void *)c0cur;

    return &cur->c0cur_es;
}

static merr_t
_c0_put(
    struct c0 *              handle,
    const struct kvs_ktuple *kt,
    const struct kvs_vtuple *vt,
    const uintptr_t          seqnoref)
{
    struct mock_c0 *m0 = mock_c0_h2r(handle);
    int             i;

    if (kt->kt_len > KEY_LEN || kvs_vtuple_vlen(vt) > VAL_LEN)
        return merr(ev(EINVAL));

    for (i = 0; i < KEY_CNT; ++i) {
        if (m0->data[i].klen == 0) {
            memcpy(&m0->data[i].key, kt->kt_data, kt->kt_len);
            memcpy(&m0->data[i].val, vt->vt_data, kvs_vtuple_vlen(vt));
            m0->data[i].klen = kt->kt_len;
            m0->data[i].xlen = vt->vt_xlen;
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
    struct mock_c0 *m0 = mock_c0_h2r(handle);
    int             i;

    if (kt->kt_len > KEY_LEN || vbuf->b_buf_sz > VAL_LEN)
        return merr(ev(EINVAL));

    for (i = 0; i < KEY_CNT; ++i) {
        if (m0->data[i].klen && memcmp(m0->data[i].key, kt->kt_data, kt->kt_len) == 0) {
            u32 copylen;

            vbuf->b_len = c0_data_vlen(&m0->data[i]);

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
_c0_del(struct c0 *handle, const struct kvs_ktuple *kt, const uintptr_t seqno)
{
    struct mock_c0 *m0 = mock_c0_h2r(handle);
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
_c0_prefix_del(struct c0 *handle, const struct kvs_ktuple *kt, u64 seqno)
{
    struct mock_c0 *m0 = mock_c0_h2r(handle);
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

    spin_lock_init(&cn->cc_lock);
    cn->cc_head = NULL;

    cn->cndb = cndb;
    *out = (void *)cn;

    return 0;
}

static merr_t
_cn_close(struct cn *h)
{
    struct mock_cn *cn = (void *)h;
    struct mock_cn_cursor *cur;

    while ((cur = cn->cc_head)) {
        cn->cc_head = cur->cc_next;
        munmap(cur, sizeof(*cur));
    }

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
    struct mock_cn_cursor *cur;

    spin_lock(&mn->cc_lock);
    cur = mn->cc_head;
    if (cur)
        mn->cc_head = cur->cc_next;
    spin_unlock(&mn->cc_lock);

    if (!cur) {
        cur = mmap(NULL, sizeof(*cur), PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
        if (cur == MAP_FAILED)
            return merr(ENOMEM);

        memset(cur->tripwire, 0xaa, sizeof(cur->tripwire));

        /* Make the tripwire pages inaccessible to catch errant
         * unmocked accesses dead in their tracks.
         */
        if (mprotect(cur, sizeof(cur->tripwire), PROT_NONE))
            return merr(errno);
    }

    memcpy(cur->prefix, prefix, pfx_len);
    cur->pfx_len = pfx_len;
    cur->seqno = seqno;
    cur->i = 0;
    cur->data = mn->data;
    cur->cn = mn;

    if (mn->data)
        qsort(mn->data, KEY_CNT, sizeof(struct c0_data), cmp);
    else
        cur->i = KEY_CNT;

    *cursorp = cur;

    return 0;
}

static void
_cn_cursor_destroy(struct cn_cursor *cursor)
{
    struct mock_cn_cursor *cur = (void *)cursor;
    struct mock_cn *cn = cur->cn;

    spin_lock(&cn->cc_lock);
    cur->cc_next = cn->cc_head;
    cn->cc_head = cur;
    spin_unlock(&cn->cc_lock);
}

static merr_t
_cn_cursor_update(struct cn_cursor *cursor, u64 seqno, bool *updated)
{
    struct mock_cn_cursor *cur = (void *)cursor;

    if (updated)
        *updated = false;

    cur->seqno = seqno;
    return 0;
}

static merr_t
_cn_cursor_read(struct cn_cursor *cursor, struct kvs_cursor_element *elem, bool *eof)
{
    struct mock_cn_cursor *cur = (void *)cursor;

    while (cur->i < KEY_CNT) {
        struct c0_data *d = &cur->data[cur->i];

        ++cur->i;
        if (d->klen) {
            if (cur->pfx_len && memcmp(d->key, cur->prefix, cur->pfx_len))
                continue;

            key2kobj(&elem->kce_kobj, d->key, d->klen);
            kvs_vtuple_init(&elem->kce_vt, (void *)d->val, d->xlen);
            *eof = false;

            return 0;
        }
    }

    *eof = true;
    return 0;
}

static merr_t
_cn_cursor_seek(
    struct cn_cursor * cursor,
    const void *       key,
    u32                len,
    struct kc_filter * filter)
{
    struct mock_cn_cursor *cur = (void *)cursor;

    if (!cur->data)
        goto missed;

    for (cur->i = 0; cur->i < KEY_CNT; ++cur->i) {
        struct c0_data *d = &cur->data[cur->i];

        if (keycmp(key, len, d->key, d->klen) <= 0)
            return 0;
    }

missed:
    return 0;
}

static bool
cncur_next(struct element_source *es, void **element) {
    struct mock_cn_cursor *cncur = container_of(es, struct mock_cn_cursor, es);
    bool eof;
    merr_t err;

    err = cn_cursor_read((void *)cncur, &cncur->elem, &eof);
    if (ev(err) || eof)
        return false;

    cncur->elem.kce_source = KCE_SOURCE_CN;
    *element = &cncur->elem;
    return true;
}

struct element_source *
_cn_cursor_es_make(struct cn_cursor *cncur) {
    struct mock_cn_cursor *cur = (void *)cncur;

	cur->es = es_make(cncur_next, 0, 0);
	return &cur->es;
}

struct element_source *
_cn_cursor_es_get(struct cn_cursor *cncur) {
    struct mock_cn_cursor *cur = (void *)cncur;

	return &cur->es;
}

merr_t
_cn_cursor_active_kvsets(struct cn_cursor *cursor, u32 *active, u32 *total)
{
    *active = 0;
    *total = 0;

    return 0;
}

/* cN mocks
 * --------
 * Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection cn_inject_list[] = {

    { mapi_idx_cn_make,              MAPI_RC_SCALAR, 0 },
    { mapi_idx_cn_ingestv,           MAPI_RC_SCALAR, 0 },
    { mapi_idx_cn_get_sfx_len,       MAPI_RC_SCALAR, 0 },
    { mapi_idx_cn_periodic,          MAPI_RC_SCALAR, 0 },
    { mapi_idx_cn_is_capped,         MAPI_RC_SCALAR, 0 },
    { mapi_idx_cn_disable_maint,     MAPI_RC_SCALAR, 0 },

    { mapi_idx_cn_get_rp,            MAPI_RC_PTR, &mocked_kvs_rparams },
    { mapi_idx_cn_get_cparams,       MAPI_RC_PTR, &mocked_kvs_cparams },
    { mapi_idx_cn_get_dataset,       MAPI_RC_PTR, NULL },
    { mapi_idx_cn_get_mclass_policy, MAPI_RC_PTR, NULL },
    { mapi_idx_cn_pc_mclass_get,     MAPI_RC_PTR, NULL },
    { mapi_idx_cn_get_ingest_perfc,  MAPI_RC_PTR, NULL },

    { -1 },
};

void
mock_cn_set()
{
    mocked_kvs_rparams = kvs_rparams_defaults();
    mocked_kvs_cparams = kvs_cparams_defaults();

    mapi_inject_list_set(cn_inject_list);

    mock_kvset_builder_set();

    MOCK_SET(cn, _cn_open);
    MOCK_SET(cn, _cn_close);
    MOCK_SET(cn, _cn_get);
    MOCK_SET(cn, _cn_ref_get);
    MOCK_SET(cn, _cn_ref_put);
    MOCK_SET(cn, _cn_hash_get);

    MOCK_SET(cn_cursor, _cn_cursor_create);
    MOCK_SET(cn_cursor, _cn_cursor_update);
    MOCK_SET(cn_cursor, _cn_cursor_read);
    MOCK_SET(cn_cursor, _cn_cursor_seek);
    MOCK_SET(cn_cursor, _cn_cursor_es_make);
    MOCK_SET(cn_cursor, _cn_cursor_es_get);
    MOCK_SET(cn_cursor, _cn_cursor_destroy);
    MOCK_SET(cn_cursor, _cn_cursor_active_kvsets);
}

void
mock_cn_unset()
{
    mapi_inject_list_unset(cn_inject_list);

    mock_kvset_builder_unset();

    MOCK_UNSET(cn, _cn_open);
    MOCK_UNSET(cn, _cn_close);
    MOCK_UNSET(cn, _cn_get);
    MOCK_UNSET(cn, _cn_ref_get);
    MOCK_UNSET(cn, _cn_ref_put);
    MOCK_UNSET(cn, _cn_hash_get);

    MOCK_UNSET(cn_cursor, _cn_cursor_create);
    MOCK_UNSET(cn_cursor, _cn_cursor_update);
    MOCK_UNSET(cn_cursor, _cn_cursor_read);
    MOCK_UNSET(cn_cursor, _cn_cursor_seek);
    MOCK_UNSET(cn_cursor, _cn_cursor_es_make);
    MOCK_UNSET(cn_cursor, _cn_cursor_es_get);
    MOCK_UNSET(cn_cursor, _cn_cursor_destroy);
    MOCK_UNSET(cn_cursor, _cn_cursor_active_kvsets);
}

/* c0 mocks
 * --------
 * Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection c0_inject_list[] = {
    { mapi_idx_c0_cursor_update,    MAPI_RC_SCALAR, 0 },
    { mapi_idx_c0_cursor_bind_txn,  MAPI_RC_SCALAR, 0 },
    { mapi_idx_c0_cursor_save,      MAPI_RC_SCALAR, 0 },
    { mapi_idx_c0_cursor_restore,   MAPI_RC_SCALAR, 0 },
    { -1 },
};

void
mock_c0_set()
{
    mapi_inject_list_set(c0_inject_list);

    MOCK_SET(c0, _c0_open);
    MOCK_SET(c0, _c0_close);
    MOCK_SET(c0, _c0_index);
    MOCK_SET(c0, _c0_hash_get);
    MOCK_SET(c0, _c0_put);
    MOCK_SET(c0, _c0_get);
    MOCK_SET(c0, _c0_del);
    MOCK_SET(c0, _c0_prefix_del);
    MOCK_SET(c0, _c0_cursor_create);
    MOCK_SET(c0, _c0_cursor_read);
    MOCK_SET(c0, _c0_cursor_seek);
    MOCK_SET(c0, _c0_cursor_es_make);
    MOCK_SET(c0, _c0_cursor_es_get);
    MOCK_SET(c0, _c0_cursor_destroy);
}

void
mock_c0_unset()
{
    mapi_inject_list_unset(c0_inject_list);

    MOCK_UNSET(c0, _c0_open);
    MOCK_UNSET(c0, _c0_close);
    MOCK_UNSET(c0, _c0_index);
    MOCK_UNSET(c0, _c0_hash_get);
    MOCK_UNSET(c0, _c0_put);
    MOCK_UNSET(c0, _c0_get);
    MOCK_UNSET(c0, _c0_del);
    MOCK_UNSET(c0, _c0_prefix_del);
    MOCK_UNSET(c0, _c0_cursor_create);
    MOCK_UNSET(c0, _c0_cursor_seek);
    MOCK_UNSET(c0, _c0_cursor_es_make);
    MOCK_UNSET(c0, _c0_cursor_es_get);
    MOCK_UNSET(c0, _c0_cursor_read);
    MOCK_UNSET(c0, _c0_cursor_destroy);
}

/*****************************************************************
 * set/unset c0 and cn mocks
 */
void
mock_c0cn_set()
{
    mock_c0_set();
    mock_cn_set();
}

void
mock_c0cn_unset()
{
    mock_cn_unset();
    mock_c0_unset();
}

/* kvdb_log mock
 * -------------
 * Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection kvdb_log_inject_list[] = {
    { mapi_idx_kvdb_log_make,       MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_open,       MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_close,      MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_rollover,   MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_done,       MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_abort,      MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_mdc_create, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvdb_log_replay,     MAPI_RC_SCALAR, 0 },
    { -1 },
};

void
mock_kvdb_log_set(void)
{
    mapi_inject_list_set(kvdb_log_inject_list);
}

void
mock_kvdb_log_unset(void)
{
    mapi_inject_list_unset(kvdb_log_inject_list);
}

/*****************************************************************
 * CNDB Mock
 */

static u64 cndb_id_mocked;

static merr_t
_cndb_alloc(struct mpool *ds, u64 *captgt, u64 *oid1, u64 *oid2)
{
    *oid1 = ++cndb_id_mocked;
    *oid2 = ++cndb_id_mocked;
    return 0;
}

static merr_t
_cndb_cn_make(struct cndb *cndb, struct kvs_cparams *cp, u64 *cnid, char *name)
{
    *cnid = ++cndb_id_mocked;
    return 0;
}

/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection cndb_inject_list[] = {
    { mapi_idx_cndb_make,         MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_replay,       MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_cnv_get,      MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_cn_info_idx,  MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_cn_count,     MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_open,         MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_close,        MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_replay,       MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_start,    MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_txc,      MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_txd,      MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_meta,     MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_ack_c,    MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_ack_d,    MAPI_RC_SCALAR, 0 },
    { mapi_idx_cndb_txn_nak,      MAPI_RC_SCALAR, 0 },
    { -1 },
};

void
mock_cndb_set()
{
    mapi_inject_list_set(cndb_inject_list);
    MOCK_SET(cndb, _cndb_alloc);
    MOCK_SET(cndb, _cndb_cn_make);
}

void
mock_cndb_unset()
{
    mapi_inject_list_unset(cndb_inject_list);
    MOCK_UNSET(cndb, _cndb_alloc);
    MOCK_UNSET(cndb, _cndb_cn_make);
}
