/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/conditions.h>
#include <hse_test_support/mock_api.h>

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/hse_err.h>
#include <hse_ikvdb/kvset_builder.h>

#include "mock_kvset_builder.h"

static merr_t
_kvset_builder_create(
    struct kvset_builder **bld_out,
    struct cn *            cn,
    struct perfc_set *     pc,
    u64                    vgroup,
    uint                   flags)
{
    struct mock_kvset_builder *mock;

    mock = mapi_safe_malloc(sizeof(*mock));
    VERIFY_TRUE_RET(mock, merr(EBUG));

    memset(mock, 0, sizeof(*mock));

    *bld_out = (struct kvset_builder *)mock;
    return 0;
}

void
_kvset_builder_set_agegroup(struct kvset_builder *bldr, enum hse_mclass_policy_age age)
{
}

static merr_t
_kvset_builder_add_key(struct kvset_builder *builder, const struct key_obj *kobj)
{
    return 0;
}

static merr_t
_kvset_builder_add_val(
    struct kvset_builder *self,
    u64                   seq,
    const void *          vdata,
    uint                  vlen,
    uint                  complen)
{
    return 0;
}

static merr_t
_kvset_builder_add_nonval(struct kvset_builder *self, u64 seq, enum kmd_vtype vtype)
{
    return 0;
}

static merr_t
_kvset_builder_add_vref(
    struct kvset_builder *self,
    u64                   seq,
    uint                  vbidx,
    uint                  vboff,
    uint                  vlen,
    uint                  complen)
{
    return 0;
}

static merr_t
_kvset_builder_get_mblocks(struct kvset_builder *bld, struct kvset_mblocks *mblks)
{
    return 0;
}

static void
_kvset_builder_destroy(struct kvset_builder *bld)
{
    mapi_safe_free(bld);
}

void
mock_kvset_builder_unset(void)
{
    MOCK_UNSET(kvset_builder, _kvset_builder_create);
    MOCK_UNSET(kvset_builder, _kvset_builder_add_key);
    MOCK_UNSET(kvset_builder, _kvset_builder_add_val);
    MOCK_UNSET(kvset_builder, _kvset_builder_add_nonval);
    MOCK_UNSET(kvset_builder, _kvset_builder_add_vref);
    MOCK_UNSET(kvset_builder, _kvset_builder_get_mblocks);
    MOCK_UNSET(kvset_builder, _kvset_builder_set_agegroup);
    MOCK_UNSET(kvset_builder, _kvset_builder_destroy);
}

void
mock_kvset_builder_set(void)
{
    /* Allow repeated init() w/o intervening unset() */
    mock_kvset_builder_unset();

    MOCK_SET(kvset_builder, _kvset_builder_create);
    MOCK_SET(kvset_builder, _kvset_builder_add_key);
    MOCK_SET(kvset_builder, _kvset_builder_add_val);
    MOCK_SET(kvset_builder, _kvset_builder_add_nonval);
    MOCK_SET(kvset_builder, _kvset_builder_add_vref);
    MOCK_SET(kvset_builder, _kvset_builder_get_mblocks);
    MOCK_SET(kvset_builder, _kvset_builder_set_agegroup);
    MOCK_SET(kvset_builder, _kvset_builder_destroy);
}
