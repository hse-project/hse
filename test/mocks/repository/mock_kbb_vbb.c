/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/conditions.h>

#include <hse_util/logging.h>
#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_test_support/mock_api.h>

#include <cn/kblock_builder.h>
#include <cn/vblock_builder.h>

#include "mock_kbb_vbb.h"
#include "mock_mpool.h"

static merr_t
_kbb_create(struct kblock_builder **bld_out, struct cn *cn, struct perfc_set *pc, uint flags)
{
    *bld_out = (struct kblock_builder *)0x1111;
    return 0;
}

static merr_t
_vbb_create(
    struct vblock_builder **bld_out,
    struct cn *             cn,
    struct perfc_set *      pc,
    u64                     vgroup,
    uint                    flags)
{
    *bld_out = (struct vblock_builder *)0x2222;
    return 0;
}

/*----------------------------------------------------------------
 * Install/Remove kbb/vbb mocks
 */

void
mock_kbb_set(void)
{
    mock_mpool_set();

    /* Allow repeated init() w/o intervening unset() */
    mock_kbb_unset();

    MOCK_SET(kblock_builder, _kbb_create);

    mapi_inject(mapi_idx_kbb_destroy, 0);
    mapi_inject(mapi_idx_kbb_add_entry, 0);
    mapi_inject(mapi_idx_kbb_add_entry, 0);
    mapi_inject(mapi_idx_kbb_add_ptomb, 0);
    mapi_inject(mapi_idx_kbb_finish, 0);
}

void
mock_kbb_unset(void)
{
    MOCK_UNSET(kblock_builder, _kbb_create);

    mapi_inject_unset(mapi_idx_kbb_destroy);
    mapi_inject_unset(mapi_idx_kbb_add_entry);
    mapi_inject_unset(mapi_idx_kbb_add_ptomb);
    mapi_inject_unset(mapi_idx_kbb_finish);
}

void
mock_vbb_set(void)
{
    mock_mpool_set();

    /* Allow repeated init() w/o intervening unset() */
    mock_vbb_unset();

    MOCK_SET(vblock_builder, _vbb_create);

    mapi_inject(mapi_idx_vbb_destroy, 0);
    mapi_inject(mapi_idx_vbb_add_entry, 0);
    mapi_inject(mapi_idx_vbb_finish, 0);
}

void
mock_vbb_unset(void)
{
    MOCK_UNSET(vblock_builder, _vbb_create);

    mapi_inject_unset(mapi_idx_vbb_destroy);
    mapi_inject_unset(mapi_idx_vbb_add_entry);
    mapi_inject_unset(mapi_idx_vbb_finish);
}
