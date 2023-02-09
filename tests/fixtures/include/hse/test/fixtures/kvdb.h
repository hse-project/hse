/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_TEST_FIXTURES_KVDB_H
#define HSE_TEST_FIXTURES_KVDB_H

#include <stddef.h>

#include <hse/types.h>

hse_err_t
fxt_kvdb_setup(
    const char *kvdb_home,
    size_t rparamc,
    const char * const *rparamv,
    size_t cparamc,
    const char * const *cparamv,
    struct hse_kvdb **kvdb);

hse_err_t
fxt_kvdb_teardown(const char *kvdb_home, struct hse_kvdb *kvdb);

#endif
