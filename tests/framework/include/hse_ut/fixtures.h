/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc. All rights reserved.
 */
#ifndef HSE_MTF_FIXTURES_H
#define HSE_MTF_FIXTURES_H

#include <hse/hse.h>

#include <hse_ut/common.h>

__attribute__((__weak__))
void
mtf_debug_hook(void);

__attribute__((__weak__))
void
mtf_print_errinfo(
    hse_err_t               err,
    const char             *fmt,
    ...);

void
mtf_print_err(
    const char             *fmt,
    ...);

int
mtf_kvdb_kvs_drop_all(
    struct hse_kvdb        *kvdb);

int
mtf_kvdb_setupv(
    struct mtf_test_info   *lcl_ti,
    struct hse_kvdb       **kvdb_out,
    va_list                 ap);

int
mtf_kvdb_setup(
    struct mtf_test_info   *lcl_ti,
    struct hse_kvdb       **kvdb,
    ...);

int
mtf_kvdb_teardown(
    struct mtf_test_info   *lcl_ti);

#endif
