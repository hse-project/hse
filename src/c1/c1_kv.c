/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "c1_private.h"
#include "c1_kv_internal.h"

_Static_assert(
    (HSE_C1_CACHE_SIZE / HSE_C1_DEFAULT_STRIPE_WIDTH) >=
        (sizeof(struct c1_kvbundle) +
         (HSE_C1_DEFAULT_STRIP_SIZE * (sizeof(struct c1_kvtuple) + sizeof(struct c1_vtuple)))),
    "Insufficient c1 kvcache size");

static merr_t
c1_kvcache_create_internal(struct c1_kvcache *cc, size_t alloc_sz)
{
    struct cheap *cheap;

    cc->c1kvc_free = true;
    mutex_init(&cc->c1kvc_lock);

    cheap = cheap_create(16, alloc_sz);
    if (!cheap)
        return merr(ev(ENOMEM));

    cc->c1kvc_cheap = cheap;

    return 0;
}

merr_t
c1_kvcache_create(struct c1 *c1)
{
    merr_t err;
    int    i;
    size_t alloc_sz;

    alloc_sz = HSE_C1_CACHE_SIZE / HSE_C1_DEFAULT_STRIPE_WIDTH;

    for (i = 0; i < HSE_C1_DEFAULT_STRIPE_WIDTH; i++) {
        err = c1_kvcache_create_internal(&c1->c1_kvc[i], alloc_sz);
        if (ev(err)) {
            while (--i >= 0)
                c1_kvcache_destroy_internal(&c1->c1_kvc[i]);
            return err;
        }
    }

    return 0;
}

BullseyeCoverageSaveOff void
c1_kvcache_destroy_internal(struct c1_kvcache *cc)
{
    mutex_destroy(&cc->c1kvc_lock);
    cheap_destroy(cc->c1kvc_cheap);
}
BullseyeCoverageRestore

    void
    c1_kvcache_destroy(struct c1 *c1)
{
    int i;

    for (i = 0; i < HSE_C1_DEFAULT_STRIPE_WIDTH; i++)
        c1_kvcache_destroy_internal(&c1->c1_kvc[i]);
}

struct c1_kvcache *
c1_get_kvcache(struct c1 *c1h)
{
    struct c1_kvcache *cc;

    int i;

    if (ev(!c1h))
        return NULL;

    for (i = 0, cc = NULL; i < HSE_C1_DEFAULT_STRIPE_WIDTH; i++) {
        bool found;

        found = false;
        cc = &c1h->c1_kvc[i];

        c1_kvcache_lock(cc);
        if (cc->c1kvc_free) {
            found = true;
            cc->c1kvc_free = false;
        }
        c1_kvcache_unlock(cc);

        if (found)
            break;

        cc = NULL;
    }

    /* cc can't be NULL, as we have 1-1 mappping between the
     * no. of io threads and the no. of c1 kv cache instances.
     * */
    assert(cc);

    return cc;
}

void
c1_put_kvcache(struct c1_kvcache *cc)
{
    c1_kvcache_lock(cc);
    cc->c1kvc_free = true;
    c1_kvcache_unlock(cc);
}

/*
 * c1 KV bundle related interfaces
 **/

merr_t
c1_kvbundle_alloc(struct c1_kvcache *cc, struct c1_kvbundle **ckvb)
{
    struct c1_kvbundle *kvb;

    kvb = c1_kvcache_alloc(cc, __alignof(*kvb), sizeof(*kvb));
    if (ev(!kvb))
        return merr(ENOMEM);

    c1_kvbundle_reset(kvb);

    *ckvb = kvb;

    return 0;
}

BullseyeCoverageSaveOff void
c1_kvbundle_reset(struct c1_kvbundle *ckvb)
{
    memset(ckvb, 0, sizeof(*ckvb));
    INIT_S_LIST_HEAD(&ckvb->c1kvb_kvth);
    ckvb->c1kvb_minseqno = U64_MAX;
}

BullseyeCoverageRestore

    void
    c1_kvbundle_add_kvt(
        struct c1_kvbundle * ckvb,
        struct c1_kvtuple *  ckvt,
        struct s_list_head **tail)
{
    /* Update the key and value count */
    ++ckvb->c1kvb_ktcount;
    ckvb->c1kvb_vtcount += ckvt->c1kvt_vt.c1vt_vcount;

    /* Add ckvt to the kv tuple list in this bundle */
    if (*tail == NULL)
        *tail = &ckvb->c1kvb_kvth;

    s_list_add_tail(&ckvt->c1kvt_next, tail);
}

BullseyeCoverageSaveOff void
c1_kvbundle_set_seqno(struct c1_kvbundle *ckvb, u64 minseqno, u64 maxseqno)
{
    if (ckvb->c1kvb_minseqno > minseqno)
        ckvb->c1kvb_minseqno = minseqno;

    if (ckvb->c1kvb_maxseqno < maxseqno)
        ckvb->c1kvb_maxseqno = maxseqno;
}
BullseyeCoverageRestore

    void
    c1_kvbundle_set_size(struct c1_kvbundle *ckvb, u64 size)
{
    ckvb->c1kvb_size = size;
}

u32
c1_kvbundle_get_ktc(struct c1_kvbundle *ckvb)
{
    return ckvb->c1kvb_ktcount;
}

u32
c1_kvbundle_get_vtc(struct c1_kvbundle *ckvb)
{
    return ckvb->c1kvb_vtcount;
}

/*
 * c1 KV tuple related interfaces
 **/

merr_t
c1_kvtuple_alloc(struct c1_kvcache *cc, struct c1_kvtuple **ckvt)
{
    struct c1_kvtuple *kvt;

    kvt = c1_kvcache_alloc(cc, __alignof(*kvt), sizeof(*kvt));
    if (ev(!kvt))
        return merr(ENOMEM);

    c1_kvtuple_reset(kvt);

    *ckvt = kvt;

    return 0;
}

void
c1_kvtuple_init(
    struct c1_kvtuple *ckvt,
    u64                klen,
    void *             data,
    u64                cnid,
    u32                skidx,
    struct bonsai_kv * bkv)
{
    struct c1_ktuple *ckt;

    ckt = &ckvt->c1kvt_kt;

    ckt->c1kt_klen = klen;
    ckt->c1kt_data = data;

    ckvt->c1kvt_cnid = cnid;
    ckvt->c1kvt_skidx = skidx;
    ckvt->c1kvt_bkv = bkv;
}

void
c1_kvtuple_reset(struct c1_kvtuple *ckvt)
{
    memset(ckvt, 0, sizeof(*ckvt));
    INIT_S_LIST_HEAD(&ckvt->c1kvt_vt.c1vt_vth);
    INIT_S_LIST_HEAD(&ckvt->c1kvt_next);
}

BullseyeCoverageSaveOff void
c1_kvtuple_addval(struct c1_kvtuple *ckvt, struct c1_vtuple *cvt, struct s_list_head **tail)
{
    struct c1_vtuple_array *cvta;

    cvta = &ckvt->c1kvt_vt;

    cvta->c1vt_vlen += cvt->c1vt_vlen;
    ++cvta->c1vt_vcount;

    if (*tail == NULL)
        *tail = &cvta->c1vt_vth;

    s_list_add_tail(&cvt->c1vt_next, tail);
}
BullseyeCoverageRestore

    /*
 * c1 value tuple related interfaces
 **/
    merr_t
    c1_vtuple_alloc(struct c1_kvcache *cc, struct c1_vtuple **cvt)
{
    struct c1_vtuple *vt;

    vt = c1_kvcache_alloc(cc, __alignof(*vt), sizeof(*vt));
    if (ev(!vt))
        return merr(ENOMEM);

    c1_vtuple_reset(vt);

    *cvt = vt;

    return 0;
}

void
c1_vtuple_init(
    struct c1_vtuple *       cvt,
    u64                      vlen,
    u64                      seqno,
    void *                   data,
    bool                     tomb)
{
    cvt->c1vt_vlen = vlen;
    cvt->c1vt_seqno = seqno;
    cvt->c1vt_data = data;
    cvt->c1vt_tomb = tomb;
}

void
c1_vtuple_reset(struct c1_vtuple *cvt)
{
    memset(cvt, 0, sizeof(*cvt));
    INIT_S_LIST_HEAD(&cvt->c1vt_next);
}
