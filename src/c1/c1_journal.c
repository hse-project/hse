/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_c1_journal

#include <mpool/mpool.h>

#include "c1_private.h"
#include "c1_journal_internal.h"

merr_t
c1_journal_create(
    struct mpool *      mp,
    u64                 seqno,
    u32                 gen,
    u64                 oid1,
    u64                 oid2,
    int                 mediaclass,
    const char *        mpname,
    u64                 dtime,
    u64                 dsize,
    u64                 capacity,
    u64                 jrnlsize,
    struct kvdb_health *health,
    struct c1_journal **out)
{
    struct c1_journal *jrnl;

    jrnl = malloc(sizeof(*jrnl));
    if (!jrnl)
        return merr(ev(ENOMEM));

    jrnl->c1j_mediaclass = mediaclass;
    jrnl->c1j_dtime = dtime;
    jrnl->c1j_dsize = dsize;
    jrnl->c1j_capacity = capacity;
    jrnl->c1j_jrnlsize = jrnlsize;
    jrnl->c1j_seqno = seqno;
    jrnl->c1j_resetseqno = 0;
    jrnl->c1j_gen = gen;
    jrnl->c1j_rdonly = false;

    jrnl->c1j_oid1 = oid1;
    jrnl->c1j_oid2 = oid2;
    jrnl->c1j_mp = mp;
    jrnl->c1j_mdc = NULL;
    jrnl->c1j_kvdb_health = health;
    atomic_set(&jrnl->c1j_treecnt, 0);
    memset(&jrnl->c1j_pcset, 0, sizeof(jrnl->c1j_pcset));
    *out = jrnl;

    c1_perfc_journal_alloc(&jrnl->c1j_pcset, mpname);

    return 0;
}

merr_t
c1_journal_alloc(struct mpool *mp, int mediaclass, u64 capacity, struct c1_journal **out)
{
    merr_t             err;
    struct c1_journal *jrnl = NULL;

    err = c1_journal_create(
        mp,
        C1_INITIAL_SEQNO,
        0,
        0,
        0,
        mediaclass,
        NULL,
        0,
        0,
        capacity,
        HSE_C1_JOURNAL_SIZE,
        NULL,
        &jrnl);
    if (ev(err))
        return err;

    assert(jrnl != NULL);

    err = c1_journal_alloc_mdc(jrnl);
    if (ev(err)) {
        free(jrnl);
        return err;
    }

    *out = jrnl;

    return 0;
}

merr_t
c1_journal_make(
    struct mpool *      mp,
    u64                 oid1,
    u64                 oid2,
    int                 mediaclass,
    u64                 capacity,
    struct c1_journal **out)
{
    merr_t             err;
    struct c1_journal *jrnl = NULL;

    err = c1_journal_create(
        mp,
        C1_INITIAL_SEQNO,
        0,
        oid1,
        oid2,
        mediaclass,
        NULL,
        HSE_C1_DEFAULT_DTIME,
        HSE_C1_DEFAULT_DSIZE,
        capacity,
        HSE_C1_JOURNAL_SIZE,
        NULL,
        &jrnl);
    if (ev(err))
        return err;

    assert(jrnl != NULL);

    err = c1_journal_commit_mdc(jrnl);
    if (ev(err))
        goto err_exit;

    err = c1_journal_open_mdc(jrnl);
    if (ev(err))
        goto err_exit;

    err = c1_journal_format(jrnl);
    if (ev(err))
        goto err_exit;

    *out = jrnl;

    return 0;

err_exit:
    c1_journal_destroy(jrnl);

    return err;
}

merr_t
c1_journal_destroy(struct c1_journal *j)
{
    struct mpool *mp;
    merr_t        err;
    u64           oid1;
    u64           oid2;

    mp = j->c1j_mp;
    oid1 = j->c1j_oid1;
    oid2 = j->c1j_oid2;

    c1_journal_close(j);

    err = c1_journal_destroy_mdc(mp, oid1, oid2);
    return err;
}

merr_t
c1_journal_open(
    int                 rdonly,
    struct mpool *      mp,
    int                 mclass,
    const char *        mpname,
    u64                 oid1,
    u64                 oid2,
    struct kvdb_health *health,
    struct c1_journal **out)
{
    merr_t             err;
    struct c1_journal *jrnl = NULL;

    err = c1_journal_create(
        mp, C1_INITIAL_SEQNO, 0, oid1, oid2, mclass, mpname, 0, 0, 0, 0, health, &jrnl);
    if (ev(err))
        return err;

    assert(jrnl != NULL);

    jrnl->c1j_rdonly = rdonly;

    err = c1_journal_open_mdc(jrnl);
    if (ev(err)) {
        free(jrnl);
        return err;
    }

    *out = jrnl;

    jrnl->c1j_resetseqno = jrnl->c1j_seqno;

    return 0;
}

merr_t
c1_journal_close(struct c1_journal *jrnl)
{
    merr_t err;

    /*
     * c1_alloc() invoke this function without opening MDC.
     */
    if (!jrnl->c1j_mdc) {
        free(jrnl);
        return 0;
    }

    err = 0;
    if (jrnl->c1j_kvdb_health)
        err = kvdb_health_check(jrnl->c1j_kvdb_health, KVDB_HEALTH_FLAG_ALL);

    if (!err && !jrnl->c1j_rdonly) {
        err = c1_journal_write_close(jrnl);
        if (ev(err))
            return err;
    }

    err = c1_journal_close_mdc(jrnl);
    if (ev(err))
        return err;

    c1_perfc_journal_free(&jrnl->c1j_pcset);

    free(jrnl);

    return err;
}

merr_t
c1_journal_alloc_mdc(struct c1_journal *jrnl)
{
    merr_t              err;
    struct mdc_capacity mdcap;
    struct mdc_props    props;
    u64                 oid1;
    u64                 oid2;
    u64                 staging_absent;

    enum mp_media_classp mclassp = MP_MED_STAGING;

    err = merr(ENOENT); /* assume this assert will fail */

    mdcap.mdt_captgt = jrnl->c1j_jrnlsize;
    mdcap.mdt_spare = false;

    staging_absent = mpool_mclass_get(jrnl->c1j_mp, MP_MED_STAGING, NULL);
    if (staging_absent)
        mclassp = MP_MED_CAPACITY;

    err = mpool_mdc_alloc(jrnl->c1j_mp, &oid1, &oid2, mclassp, &mdcap, &props);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: mpool_mdc_alloc mclass:%d failed: @@e", err, __func__, mclassp);
        return err;
    }

    jrnl->c1j_mediaclass = props.mdc_mclassp;
    jrnl->c1j_oid1 = oid1;
    jrnl->c1j_oid2 = oid2;

    return ev(err);
}

merr_t
c1_journal_commit_mdc(struct c1_journal *jrnl)
{
    merr_t err;

    err = mpool_mdc_commit(jrnl->c1j_mp, jrnl->c1j_oid1, jrnl->c1j_oid2);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: mpool_mdc_commit failed: @@e", err, __func__);
        return err;
    }

    return 0;
}

merr_t
c1_journal_destroy_mdc(struct mpool *mp, u64 oid1, u64 oid2)
{
    merr_t err;

    err = mpool_mdc_delete(mp, oid1, oid2);
    if (ev(err))
        hse_elog(
            HSE_ERR "%s: destroy (%lx,%lx) failed: @@e", err, __func__, (ulong)oid1, (ulong)oid2);

    return err;
}

merr_t
c1_journal_open_mdc(struct c1_journal *jrnl)
{
    struct mpool_mdc *mdc;
    merr_t            err;

    err = mpool_mdc_open(jrnl->c1j_mp, jrnl->c1j_oid1, jrnl->c1j_oid2, 0, &mdc);
    if (ev(err))
        return err;

    jrnl->c1j_mdc = mdc;

    return 0;
}

merr_t
c1_journal_close_mdc(struct c1_journal *jrnl)
{
    merr_t err;

    err = mpool_mdc_close(jrnl->c1j_mdc);
    if (ev(err))
        return err;

    jrnl->c1j_mdc = NULL;

    return 0;
}

BullseyeCoverageSaveOff
merr_t
c1_journal_compact_begin(struct c1_journal *jrnl)
{
    assert(jrnl->c1j_mdc != NULL);

    return mpool_mdc_cstart(jrnl->c1j_mdc);
}

merr_t
c1_journal_compact_end(struct c1_journal *jrnl)
{
    assert(jrnl->c1j_mdc != NULL);

    return mpool_mdc_cend(jrnl->c1j_mdc);
}

merr_t
c1_journal_format(struct c1_journal *jrnl)
{
    merr_t err;

    err = c1_journal_write_version(jrnl);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1_write_version failed: @@e", err, __func__);
        return err;
    }

    err = c1_journal_write_info(jrnl);
    if (ev(err)) {
        hse_elog(HSE_ERR "%s: c1_write_info failed: @@e", err, __func__);
        return err;
    }

    return 0;
}
BullseyeCoverageRestore

merr_t
c1_journal_replay(struct c1 *c1, struct c1_journal *jrnl, c1_journal_replay_cb *cb)
{
    return c1_journal_replay_impl(c1, jrnl, cb);
}

merr_t
c1_journal_flush(struct c1_journal *jrnl)
{
    return mpool_mdc_sync(jrnl->c1j_mdc);
}

void
c1_journal_set_info(struct c1_journal *jrnl, u64 dtime, u64 dsize)
{

    if (dtime)
        jrnl->c1j_dtime = dtime;

    if (dsize)
        jrnl->c1j_dsize = dsize;
}

void
c1_journal_get_info(struct c1_journal *jrnl, u64 *dtime, u64 *dsize, u64 *dcapacity)
{
    if (dtime)
        *dtime = jrnl->c1j_dtime;

    if (dsize)
        *dsize = jrnl->c1j_dsize;

    if (dcapacity)
        *dcapacity = jrnl->c1j_capacity;
}

bool
c1_journal_reaching_capacity(struct c1_journal *jrnl)
{
    size_t size;
    merr_t err;

    err = mpool_mdc_usage(jrnl->c1j_mdc, &size);
    if (ev(err))
        return false;

    if (size > ((HSE_C1_JOURNAL_SIZE * 75) / 100))
        return true;

    return false;
}

merr_t
c1_journal_reset_tree(struct c1_journal *jrnl, u64 seqno, u32 gen, u64 newseqno, u64 newgen)
{
    struct c1_reset_omf omf;
    merr_t              err;
    u64                 start = 0;

    assert(jrnl->c1j_resetseqno < newseqno);

    c1_set_hdr(&omf.hdr, C1_TYPE_RESET, sizeof(omf));

    omf_set_c1reset_seqno(&omf, seqno);
    omf_set_c1reset_newseqno(&omf, newseqno);
    omf_set_c1reset_gen(&omf, gen);
    omf_set_c1reset_newgen(&omf, newgen);

    C1_JOURNAL_START_PERF(jrnl, start);

    err = mpool_mdc_append(jrnl->c1j_mdc, &omf, sizeof(omf), true);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mdc_append failed: @@e", err, __func__);

    c1_journal_rec_perf(jrnl, start, err);

    jrnl->c1j_resetseqno++;

    return ev(err);
}

merr_t
c1_journal_complete_tree(struct c1_journal *jrnl, u64 seqno, u32 gen, u64 kvseqno)
{
    struct c1_complete_omf omf;
    merr_t                 err;
    u64                    start = 0;

    c1_set_hdr(&omf.hdr, C1_TYPE_COMPLETE, sizeof(omf));

    omf_set_c1comp_seqno(&omf, seqno);
    omf_set_c1comp_gen(&omf, gen);
    omf_set_c1comp_kvseqno(&omf, kvseqno);

    C1_JOURNAL_START_PERF(jrnl, start);

    err = mpool_mdc_append(jrnl->c1j_mdc, &omf, sizeof(omf), false);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mdc_append failed: @@e", err, __func__);

    c1_journal_rec_perf(jrnl, start, err);

    return ev(err);
}

BullseyeCoverageSaveOff
merr_t
c1_journal_write_version(struct c1_journal *jrnl)
{
    struct c1_ver_omf ver;
    merr_t            err;
    u64               start = 0;

    /* The binary version is written in the VERSION record. */
    c1_set_hdr(&ver.hdr, C1_TYPE_VERSION, sizeof(ver));
    omf_set_c1ver_magic(&ver, C1_MAGIC);
    omf_set_c1ver_version(&ver, C1_VERSION);

    C1_JOURNAL_START_PERF(jrnl, start);

    err = mpool_mdc_append(jrnl->c1j_mdc, &ver, sizeof(ver), false);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mdc_append failed: @@e", err, __func__);

    c1_journal_rec_perf(jrnl, start, err);

    return ev(err);
}
BullseyeCoverageRestore

merr_t
c1_journal_write_info(struct c1_journal *jrnl)
{
    struct c1_info_omf info;
    merr_t             err;
    u64                start = 0;

    c1_set_hdr(&info.hdr, C1_TYPE_INFO, sizeof(info));
    omf_set_c1info_seqno(&info, jrnl->c1j_seqno);
    omf_set_c1info_gen(&info, jrnl->c1j_gen);
    omf_set_c1info_capacity(&info, jrnl->c1j_capacity);

    C1_JOURNAL_START_PERF(jrnl, start);

    err = mpool_mdc_append(jrnl->c1j_mdc, &info, sizeof(info), false);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mdc_append failed: @@e", err, __func__);

    c1_journal_rec_perf(jrnl, start, err);

    return ev(err);
}

merr_t
c1_journal_write_close(struct c1_journal *jrnl)
{
    struct c1_close_omf close;
    merr_t              err;
    u64                 start = 0;

    c1_set_hdr(&close.hdr, C1_TYPE_CLOSE, sizeof(close));

    C1_JOURNAL_START_PERF(jrnl, start);

    err = mpool_mdc_append(jrnl->c1j_mdc, &close, sizeof(close), false);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mdc_append failed: @@e", err, __func__);

    c1_journal_rec_perf(jrnl, start, err);

    return ev(err);
}

merr_t
c1_journal_write_desc(struct c1_journal *jrnl, u32 state, u64 oid, u64 seqno, u64 gen)
{
    struct c1_desc_omf desc;
    merr_t             err;
    u64                start = 0;

    c1_set_hdr(&desc.hdr, C1_TYPE_DESC, sizeof(desc));

    omf_set_c1desc_oid(&desc, oid);
    omf_set_c1desc_seqno(&desc, seqno);
    omf_set_c1desc_state(&desc, state);
    omf_set_c1desc_gen(&desc, gen);

    C1_JOURNAL_START_PERF(jrnl, start);

    err = mpool_mdc_append(jrnl->c1j_mdc, &desc, sizeof(desc), false);
    if (ev(err))
        hse_elog(HSE_ERR "%s: mpool_mdc_append failed: @@e", err, __func__);

    c1_journal_rec_perf(jrnl, start, err);

    return ev(err);
}

void
c1_journal_rec_perf(struct c1_journal *jrnl, u64 start, merr_t err)
{
    if (PERFC_ISON(&jrnl->c1j_pcset) && ((err) == 0)) {
        perfc_rec_lat(&jrnl->c1j_pcset, PERFC_LT_C1_JRNL, start);
        perfc_inc(&jrnl->c1j_pcset, PERFC_BA_C1_JRNL);
    }
}

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE == 1
#include "c1_journal_ut_impl.i"
#endif /* HSE_UNIT_TEST_MODE */
