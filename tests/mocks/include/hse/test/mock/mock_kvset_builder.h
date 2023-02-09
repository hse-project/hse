/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef MOCKS_MOCK_KVSET_BUILDERH
#define MOCKS_MOCK_KVSET_BUILDERH

struct mpool;
struct kvs_rparams;
struct mtf_test_info;

struct mock_kvset_builder {
    struct kvs_rparams *rp;
    struct mtf_test_info *lcl_ti;
};

void
mock_kvset_builder_set(void);
void
mock_kvset_builder_unset(void);

#endif
