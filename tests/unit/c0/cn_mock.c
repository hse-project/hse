/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/test/support/random_buffer.h>

#include <hse/util/platform.h>
#include <hse/util/event_counter.h>

#include <hse/ikvdb/cn.h>
#include <hse/ikvdb/c0_kvmultiset.h>

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
_cn_ingest(struct cn *cn, struct kvset_mblocks *childv, u64 txid)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    assert(mock_cn->integrity_check == INTEGRITY_CHECK);

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
    uint64_t              *kvsetidv,
    uint                   ingestc,
    u64                    ingestid,
    u64                    txhorizon,
    u64                   *min_seqno_out,
    u64                   *max_seqno_out)
{
    int    i;
    merr_t err = 0;

    for (i = 0; !err && i < ingestc; i++) {

        if (!cn[i] || !mbv[1])
            continue;

        err = _cn_ingest(cn[i], mbv[i], 0);
    }

    return err;
}

struct kvs_cparams *
_cn_get_cparams(const struct cn *cn)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    return mock_cn->cp;
}

struct kvs_rparams *
_cn_get_rp(const struct cn *cn)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    return &mock_cn->rp;
}

unsigned
mock_cn_best_ingest_count(struct cn *cn, unsigned avg_key_len)
{
    struct mock_cn *mock_cn = (struct mock_cn *)cn;

    return mock_cn->ingest_count;
}

/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
struct mapi_injection inject_list[] = {
    { mapi_idx_cn_disable_maint, MAPI_RC_SCALAR, 0},
    { mapi_idx_cn_get_cnid, MAPI_RC_SCALAR, 1},
    { mapi_idx_cn_disable_maint, MAPI_RC_SCALAR, 0},
    { -1 }
};


merr_t
create_mock_cn(
    struct cn **cn,
    bool        delay_merge,
    bool        random_release,
    u32         pfx_len)
{
    struct mock_cn *mock_cn;

    mock_cn = calloc(1, sizeof(struct kvs_cparams) + sizeof(*mock_cn));
    if (!mock_cn)
        return merr(ENOMEM);

    mock_cn->cp = (void *)(mock_cn + 1);

    MOCK_SET(cn, _cn_ingestv);
    MOCK_SET(cn, _cn_get_cparams);
    MOCK_SET(cn, _cn_get_rp);

    mapi_inject_list_set(inject_list);

    mock_cn->cp->pfx_len = pfx_len;

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
