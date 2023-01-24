/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <hse/test/mock/api.h>

#include <hse/error/merr.h>

#include <hse/ikvdb/kvset_builder.h>

#include <hse/test/mock/mock_kvset_builder.h>

static merr_t
_kvset_builder_create(
    struct kvset_builder **bld_out,
    struct cn *            cn,
    struct perfc_set *     pc,
    uint64_t               vgroup)
{
    struct mock_kvset_builder *mock;

    mock = mapi_safe_malloc(sizeof(*mock));
    if (!mock)
        return merr(EBUG);

    memset(mock, 0, sizeof(*mock));

    *bld_out = (struct kvset_builder *)mock;
    return 0;
}

static void
_kvset_builder_destroy(struct kvset_builder *bld)
{
    mapi_safe_free(bld);
}


/* Prefer the mapi_inject_list method for mocking functions over the
 * MOCK_SET/MOCK_UNSET macros if the mock simply needs to return a
 * constant value.  The advantage of the mapi_inject_list approach is
 * less code (no need to define a replacement function) and easier
 * maintenance (will not break when the mocked function signature
 * changes).
 */
static struct mapi_injection inject_list[] = {
    { mapi_idx_kvset_builder_add_key, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_builder_add_nonval, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_builder_add_val, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_builder_add_vref, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_builder_get_mblocks, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_builder_set_agegroup, MAPI_RC_SCALAR, 0 },
    { mapi_idx_kvset_builder_adopt_vblocks, MAPI_RC_SCALAR, 0},
    { -1},
};

void
mock_kvset_builder_set(void)
{
    MOCK_SET(kvset_builder, _kvset_builder_create);
    MOCK_SET(kvset_builder, _kvset_builder_destroy);

    mapi_inject_list_set(inject_list);
}

void
mock_kvset_builder_unset(void)
{
    MOCK_UNSET(kvset_builder, _kvset_builder_create);
    MOCK_UNSET(kvset_builder, _kvset_builder_destroy);

    mapi_inject_list_unset(inject_list);
}
