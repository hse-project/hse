/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSE_TEST_FIXTURES_KVS_H
#define HSE_TEST_FIXTURES_KVS_H

#include <stddef.h>

#include <hse/types.h>

hse_err_t
fxt_kvs_setup(
    struct hse_kvdb *  kvdb,
    const char *       kvs_name,
    size_t             rparamc,
    const char *const *rparamv,
    size_t             cparamc,
    const char *const *cparamv,
    struct hse_kvs **  kvs);

hse_err_t
fxt_kvs_teardown(struct hse_kvdb *kvdb, const char *kvs_name, struct hse_kvs *kvs);

#endif
