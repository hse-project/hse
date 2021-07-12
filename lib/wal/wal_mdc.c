/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/page.h>

#include <mpool/mpool.h>

#include "wal.h"
#include "wal_omf.h"
#include "wal_mdc.h"


#define WAL_BUF_SZ  (PAGE_SIZE)

struct wal_mdc {
    struct mpool_mdc *mp_mdc;
    char             *buf;
};

merr_t
wal_mdc_create(
    struct mpool     *mp,
    enum mpool_mclass mclass,
    size_t            capacity,
    uint64_t         *mdcid1,
    uint64_t         *mdcid2)
{
    merr_t err;

    if (!mp || !mdcid1 || !mdcid2)
        return merr(EINVAL);

    *mdcid1 = 0;
    *mdcid2 = 0;

    err = mpool_mdc_alloc(mp, WAL_MAGIC, capacity, mclass, mdcid1, mdcid2);
    if (err)
        return err;

    err = mpool_mdc_commit(mp, *mdcid1, *mdcid2);
    if (err)
        return err;

    return 0;
}

void
wal_mdc_destroy(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2)
{
    merr_t err;

    err = mpool_mdc_delete(mp, mdcid1, mdcid2);
    if (err)
        hse_elog(HSE_WARNING "%s: delete mdc %lx %lx failed: @@e", err, __func__, mdcid1, mdcid2);
}

merr_t
wal_mdc_open(struct mpool *mp, uint64_t mdcid1, uint64_t mdcid2, struct wal_mdc **handle)
{
    struct wal_mdc   *mdc;
    struct mpool_mdc *mp_mdc;
    merr_t err;
    size_t sz;

    if (!mp || !handle)
        return merr(EINVAL);

    err = mpool_mdc_open(mp, mdcid1, mdcid2, &mp_mdc);
    if (err)
        return err;

    sz = sizeof(*mdc) + WAL_BUF_SZ;
    mdc = calloc(1, sz);
    if (!mdc) {
        mpool_mdc_close(mp_mdc);
        return merr(ENOMEM);
    }

    mdc->mp_mdc = mp_mdc;
    mdc->buf = (char *)(mdc + 1);

    *handle = mdc;

    return 0;
}

merr_t
wal_mdc_close(struct wal_mdc *mdc)
{
    merr_t err;

    if (!mdc)
        return merr(EINVAL);

    if (mdc->mp_mdc) {
        err = mpool_mdc_close(mdc->mp_mdc);
        ev(err);
    }

    free(mdc);

    return 0;
}

merr_t
wal_mdc_sync(struct wal_mdc *mdc)
{
    return mpool_mdc_sync(mdc->mp_mdc);
}

static inline void
wal_mdchdr_pack(enum wal_rec_type rtype, char *outbuf)
{
    struct wal_mdchdr_omf *homf = (struct wal_mdchdr_omf *)outbuf;

    omf_set_mh_rtype(homf, rtype);
    omf_set_mh_rsvd(homf, 0);
}

static inline enum wal_rec_type
wal_mdchdr_rtype_get(char *inbuf)
{
    struct wal_mdchdr_omf *homf = (struct wal_mdchdr_omf *)inbuf;

    return omf_mh_rtype(homf);
}

static merr_t
wal_mdc_version_write_impl(struct wal_mdc *mdc, uint32_t version, bool sync)
{
    struct wal_version_omf vomf;
    merr_t err;

    wal_mdchdr_pack(WAL_RT_VERSION, (char *)&vomf);
    omf_set_ver_version(&vomf, version);
    omf_set_ver_magic(&vomf, WAL_MAGIC);

    err = mpool_mdc_append(mdc->mp_mdc, &vomf, sizeof(vomf), sync);
    if (err)
        return err;

    return 0;
}

merr_t
wal_mdc_version_write(struct wal_mdc *mdc, struct wal *wal, bool sync)
{
    if (!mdc || !wal)
        return merr(EINVAL);

    return wal_mdc_version_write_impl(mdc, wal_version_get(wal), sync);
}

static merr_t
wal_mdc_version_unpack(const char *buf, struct wal *wal)
{
    struct wal_version_omf *vomf;
    uint32_t version;

    if (!buf || !wal)
        return merr(EINVAL);

    vomf = (struct wal_version_omf *)buf;

    version = omf_ver_version(vomf);
    wal_version_set(wal, version);

    if (WAL_MAGIC != omf_ver_magic(vomf))
        return merr(EBADMSG);

    return 0;
}

static merr_t
wal_mdc_config_write_impl(
    struct wal_mdc   *mdc,
    uint32_t          dur_ms,
    uint32_t          dur_bytes,
    enum mpool_mclass mclass,
    bool              sync)
{
    struct wal_config_omf comf;
    merr_t err;

    wal_mdchdr_pack(WAL_RT_CONFIG, (char *)&comf);
    omf_set_cfg_durms(&comf, dur_ms);
    omf_set_cfg_durbytes(&comf, dur_bytes);
    omf_set_cfg_mclass(&comf, mclass);
    omf_set_cfg_rsvd1(&comf, 0);
    omf_set_cfg_rsvd2(&comf, 0);
    omf_set_cfg_rsvd3(&comf, 0);

    err = mpool_mdc_append(mdc->mp_mdc, &comf, sizeof(comf), sync);
    if (err)
        return err;

    return 0;
}

merr_t
wal_mdc_config_write(struct wal_mdc *mdc, struct wal *wal, bool sync)
{
    uint32_t dur_ms, dur_bytes;
    enum mpool_mclass mclass;

    if (!mdc || !wal)
        return merr(EINVAL);

    wal_dur_params_get(wal, &dur_ms, &dur_bytes, &mclass);

    return wal_mdc_config_write_impl(mdc, dur_ms, dur_bytes, mclass, sync);
}


static merr_t
wal_mdc_config_unpack(const char *buf, struct wal *wal)
{
    struct wal_config_omf *comf;
    uint32_t dur_ms, dur_bytes;
    enum mpool_mclass mclass;

    if (!buf || !wal)
        return merr(EINVAL);

    comf = (struct wal_config_omf *)buf;

    dur_ms = omf_cfg_durms(comf);
    dur_bytes = omf_cfg_durbytes(comf);
    mclass = omf_cfg_mclass(comf);
    wal_dur_params_set(wal, dur_ms, dur_bytes, mclass);

    return 0;
}

merr_t
wal_mdc_close_write(struct wal_mdc *mdc, bool sync)
{
    struct wal_close_omf comf;
    merr_t err;

    if (!mdc)
        return merr(EINVAL);

    wal_mdchdr_pack(WAL_RT_CLOSE, (char *)&comf);

    err = mpool_mdc_append(mdc->mp_mdc, &comf, sizeof(comf), sync);
    if (err)
        return err;

    return 0;
}

merr_t
wal_mdc_format(
    struct wal_mdc   *mdc,
    uint32_t          version,
    uint32_t          dur_ms,
    uint32_t          dur_bytes,
    enum mpool_mclass mclass)
{
    merr_t err;
    bool sync = true;

    err = wal_mdc_version_write_impl(mdc, version, sync);
    if (err)
        return err;

    err = wal_mdc_config_write_impl(mdc, dur_ms, dur_bytes, mclass, sync);
    if (err)
        return err;

    return 0;
}

merr_t
wal_mdc_compact(struct wal_mdc *mdc, struct wal *wal)
{
    merr_t err;
    bool sync = false;

    err = mpool_mdc_cstart(mdc->mp_mdc);
    if (err) {
        mdc->mp_mdc = NULL;
        return err;
    }

    err = wal_mdc_version_write(mdc, wal, sync);
    if (err)
        return err;

    err = wal_mdc_config_write(mdc, wal, sync);
    if (err)
        return err;

    err = mpool_mdc_cend(mdc->mp_mdc);
    if (err) {
        mdc->mp_mdc = NULL;
        return err;
    }

    return 0;
}

merr_t
wal_mdc_replay(struct wal_mdc *mdc, struct wal *wal)
{
    bool first_rec = true;
    merr_t err = 0;

    err = mpool_mdc_rewind(mdc->mp_mdc);
    if (err)
        return err;

    while (!err) {
        enum wal_rec_type rtype;
        size_t rdlen;

        err = mpool_mdc_read(mdc->mp_mdc, mdc->buf, WAL_BUF_SZ, &rdlen);
        if (rdlen == 0 || err)
            break;

        rtype = wal_mdchdr_rtype_get(mdc->buf);

        if (first_rec && rtype != WAL_RT_VERSION) {
            err = merr(EBADMSG); /* VERSION must be the first record */
            break;
        }
        first_rec = false;

        switch (rtype) {
            case WAL_RT_VERSION:
                err = wal_mdc_version_unpack(mdc->buf, wal);
                break;

            case WAL_RT_CONFIG:
                err = wal_mdc_config_unpack(mdc->buf, wal);
                break;

            case WAL_RT_CLOSE:
                /* Indication of graceful close, nothing to do for now. */
                break;

            default: /* Invalid record type */
                err = merr(EBADMSG);
                break;
        }
    };

    return err;
}
