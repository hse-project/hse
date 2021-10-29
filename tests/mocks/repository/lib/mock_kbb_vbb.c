/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>

#include <mock/api.h>

#include <cn/kblock_builder.h>
#include <cn/vblock_builder.h>

#include <mocks/mock_kbb_vbb.h>
#include <mocks/mock_mpool.h>

static merr_t
_kbb_create(struct kblock_builder **bld_out, struct cn *cn, struct perfc_set *pc)
{
    *bld_out = (struct kblock_builder *)0x1111;
    return 0;
}

static merr_t
_vbb_create(
    struct vblock_builder **bld_out,
    struct cn *             cn,
    struct perfc_set *      pc,
    u64                     vgroup)
{
    *bld_out = (struct vblock_builder *)0x2222;
    return 0;
}

/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection inject_list[] = {
    /* kblock builder */
    { mapi_idx_kbb_destroy, MAPI_RC_SCALAR, 0},
    { mapi_idx_kbb_add_entry, MAPI_RC_SCALAR, 0},
    { mapi_idx_kbb_add_entry, MAPI_RC_SCALAR, 0},
    { mapi_idx_kbb_add_ptomb, MAPI_RC_SCALAR, 0},
    { mapi_idx_kbb_finish, MAPI_RC_SCALAR, 0},
    /* vblock builder */
    { mapi_idx_vbb_destroy, MAPI_RC_SCALAR, 0},
    { mapi_idx_vbb_add_entry, MAPI_RC_SCALAR, 0},
    { mapi_idx_vbb_finish, MAPI_RC_SCALAR, 0},
    /* required termination */
    { -1 },
};

void
mock_kbb_vbb_set(void)
{
    mock_mpool_set();

    MOCK_SET(kblock_builder, _kbb_create);
    MOCK_SET(vblock_builder, _vbb_create);

    mapi_inject_list_set(inject_list);
}

void
mock_kbb_vbb_unset(void)
{
    mock_mpool_unset();

    MOCK_UNSET(kblock_builder, _kbb_create);
    MOCK_UNSET(vblock_builder, _vbb_create);

    mapi_inject_list_unset(inject_list);
}
