/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MOCKS_MOCK_KVSET_BUILDERH
#define MOCKS_MOCK_KVSET_BUILDERH

struct mpool;
struct kvs_rparams;
struct mtf_test_info;

struct mock_kvset_builder {
    struct kvs_rparams *  rp;
    struct mtf_test_info *lcl_ti;
};

void
mock_kvset_builder_set(void);
void
mock_kvset_builder_unset(void);

#endif
