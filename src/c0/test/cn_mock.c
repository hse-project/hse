/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>

#include <hse_ikvdb/cn.h>
#include <hse_ikvdb/c0_kvmultiset.h>

#include <hse_test_support/random_buffer.h>

#include <hse_util/platform.h>

#include "cn_mock.h"

#define INTEGRITY_CHECK 0x12345678

struct mock_cn {
    int                 integrity_check;
    int                 delay_merge;
    int                 random_release;
    int                 ingest_count;
    struct kvs_cparams *cp;

    struct kvs_rparams rp;
};

merr_t
_cn_ingest(struct cn *cn, struct kvset_mblocks *childv, unsigned int childc, u64 txid)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    assert(mock_cn->integrity_check == INTEGRITY_CHECK);

    if (mock_cn->rp.cn_diag_mode)
        return merr(ev(EROFS));

    if (mock_cn->delay_merge) {

        struct timespec delay;
        u32             mmd_delay;

        if (mock_cn->random_release)
            mmd_delay = generate_random_u32(1, 2000);
        else
            mmd_delay = 5;

        delay.tv_sec = 0;
        delay.tv_nsec = mmd_delay * 1000 * 1000;
        nanosleep(&delay, 0);
    }

    return 0;
}

merr_t
_cn_ingestv(
    struct cn **           cn,
    struct kvset_mblocks **mbv,
    int *                  mbc,
    u32 *                  vcommitted,
    u64                    ingestid,
    int                    ingestc,
    bool *                 ingested,
    u64 *                  seqno)
{
    int    i;
    merr_t err = 0;

    for (i = 0; !err && i < ingestc; i++) {

        if (!cn[i] || !mbv[1] || !mbc[i])
            continue;

        err = _cn_ingest(cn[i], mbv[i], (uint)mbc[i], 0);
    }

    if (err) {
        *ingested = false;
        *seqno = 0;
    } else {
        *ingested = true;
        *seqno = 10000;
    }

    return err;
}

struct kvs_cparams *
_cn_get_cparams(const struct cn *cn)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    return mock_cn->cp;
}

unsigned
mock_cn_best_ingest_count(struct cn *cn, unsigned avg_key_len)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    return mock_cn->ingest_count;
}

merr_t
create_mock_cn(
    struct cn **        cn,
    bool                delay_merge,
    bool                random_release,
    struct kvs_rparams *rp,
    u32                 pfx_len)
{
    struct mock_cn *mock_cn;

    mock_cn = calloc(1, sizeof(struct kvs_cparams) + sizeof(*mock_cn));
    if (!mock_cn)
        return merr(ENOMEM);

    mock_cn->cp = (void *)(mock_cn + 1);

    MOCK_SET(cn, _cn_ingestv);
    MOCK_SET(cn, _cn_get_cparams);

    mock_cn->cp->cp_fanout = 16;
    mock_cn->cp->cp_pfx_len = pfx_len;
    mapi_inject(mapi_idx_cn_disable_maint, 0);
    mapi_inject(mapi_idx_cn_get_cnid, 1);
    mapi_inject(mapi_idx_cn_get_rp, 0);
    mapi_inject(mapi_idx_cn_get_tbkt_maint, 0);

    mapi_inject(mapi_idx_cn_disable_maint, 0);

    mock_cn->integrity_check = INTEGRITY_CHECK;
    mock_cn->delay_merge = delay_merge;
    mock_cn->random_release = random_release;
    mock_cn->rp = kvs_rparams_defaults();

    *cn = (struct cn *)mock_cn;

    return 0;
}

void
destroy_mock_cn(struct cn *cn)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    assert(mock_cn->integrity_check == INTEGRITY_CHECK);
    free(mock_cn);
}
