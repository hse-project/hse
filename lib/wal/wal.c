/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdalign.h>

#include <hse_util/platform.h>
#include <hse_util/bonsai_tree.h>

#include <hse_ikvdb/ikvdb.h>
#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/limits.h>
#include <hse_ikvdb/key_hash.h>

#include <mpool/mpool.h>

#include "wal.h"
#include "wal_buffer.h"
#include "wal_omf.h"
#include "wal_mdc.h"


struct wal {
    struct mpool      *mp;
    struct wal_buffer *wbuf;
    struct wal_mdc    *mdc;

    uint64_t rdgen;
    uint32_t version;
    uint32_t dur_intvl;
    uint32_t dur_sz;

    atomic64_t rid HSE_ALIGNED(SMP_CACHE_BYTES);
};


/*
 * WAL data plane
 */
merr_t
wal_put(
    struct wal *wal,
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    u64 seqno)
{
    const size_t kvalign = alignof(uint64_t);
    struct wal_rec_omf *rec;
    uint64_t len, rid, cnid;
    size_t klen, vlen, rlen, kvlen;
    char *kvdata;

    klen = kt->kt_len;
    vlen = kvs_vtuple_vlen(vt);
    rlen = wal_rec_len();
    kvlen = ALIGN(klen, kvalign) + ALIGN(vlen, kvalign);
    len = rlen + kvlen;

    rec = wal_buffer_alloc(wal->wbuf, len);
    cnid = cn_get_cnid(kvs_cn(kvs));
    rid = atomic64_inc_return(&wal->rid);

    wal_rechdr_pack(WAL_RT_NONTX, rid, kvlen, (char *)rec);
    wal_rec_pack(WAL_OP_PUT, cnid, 0, seqno, klen, vt->vt_xlen, (char *)rec);

    kvdata = (char *)rec + rlen;
    memcpy(kvdata, kt->kt_data, klen);
    kt->kt_data = kvdata;
    kt->kt_flags = HSE_BTF_MANAGED;

    if (vlen > 0) {
        kvdata = PTR_ALIGN(kvdata + klen, kvalign);
        memcpy(kvdata, vt->vt_data, vlen);
        vt->vt_data = kvdata;
    }

    wal_rechdr_crc_pack((char *)rec, len);

    return 0;
}

/*
 * WAL control plane
 */

merr_t
wal_create(struct mpool *mp, uint64_t *mdcid1, uint64_t *mdcid2)
{
    struct wal_mdc *mdc;
    merr_t err;

    err = wal_mdc_create(mp, MP_MED_CAPACITY, WAL_MDC_CAPACITY, mdcid1, mdcid2);
    if (err)
        return err;

    err = wal_mdc_open(mp, *mdcid1, *mdcid2, &mdc);
    if (err) {
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);
        return err;
    }

    err = wal_mdc_format(mdc, WAL_VERSION, WAL_DUR_INTVL_MS, WAL_DUR_SZ_BYTES);

    wal_mdc_close(mdc);

    if (err)
        wal_mdc_destroy(mp, *mdcid1, *mdcid2);

    return err;
}

merr_t
wal_destroy(struct mpool *mp, uint64_t oid1, uint64_t oid2)
{
    return wal_mdc_destroy(mp, oid1, oid2);
}

merr_t
wal_open(struct mpool *mp, bool rdonly, uint64_t mdcid1, uint64_t mdcid2, struct wal **wal_out)
{
    struct wal *wal;
    struct wal_buffer *wbuf;
    struct wal_mdc *mdc;
    merr_t err;

    if (!mp || !wal_out)
        return merr(EINVAL);

    wal = calloc(1, sizeof(*wal));
    if (!wal)
        return merr(ENOMEM);

    wbuf = wal_buffer_create();
    if (!wbuf) {
        free(wal);
        return merr(ENOMEM);
    }

    err = wal_mdc_open(mp, mdcid1, mdcid2, &mdc);
    if (err)
        goto errout;

    wal->rdgen = 0;
    wal->version = WAL_VERSION;
    wal->dur_intvl = WAL_DUR_INTVL_MS;
    wal->dur_sz = WAL_DUR_SZ_BYTES;
    atomic64_set(&wal->rid, 0);

    wal->mp = mp;
    wal->wbuf = wbuf;
    wal->mdc = mdc;

    err = wal_mdc_replay(mdc, wal);
    if (err) {
        wal_mdc_close(mdc);
        goto errout;
    }

    *wal_out = wal;

    return 0;

errout:
    wal_buffer_destroy(wbuf);
    free(wal);

    return err;
}

merr_t
wal_close(struct wal *wal)
{
    merr_t err;

    if (!wal)
        return 0;

    err = wal_mdc_close(wal->mdc);
    ev(err);

    wal_buffer_destroy(wal->wbuf);
    free(wal);

    return err;
}

/*
 * get/set interfaces for struct wal fields
 */
void
wal_dur_params_get(struct wal *wal, uint32_t *dur_intvl, uint32_t *dur_sz)
{
    *dur_intvl = wal->dur_intvl;
    *dur_sz = wal->dur_sz;
}

void
wal_dur_params_set(struct wal *wal, uint32_t dur_intvl, uint32_t dur_sz)
{
    wal->dur_intvl = dur_intvl;
    wal->dur_sz = dur_sz;
}

uint64_t
wal_reclaim_dgen_get(struct wal *wal)
{
    return wal->rdgen;
}

void
wal_reclaim_dgen_set(struct wal *wal, uint64_t rdgen)
{
    wal->rdgen = rdgen;
}

uint32_t
wal_version_get(struct wal *wal)
{
    return wal->version;
}

void
wal_version_set(struct wal *wal, uint32_t version)
{
    wal->version = version;
}

