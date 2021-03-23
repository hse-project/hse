/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */
#ifndef HSE_MAPI_MALLOC_TESTER_H
#define HSE_MAPI_MALLOC_TESTER_H

#if HSE_MOCKING

struct mtf_test_info;

typedef void(mapi_alloc_tester_run_fn)(struct mtf_test_info *, unsigned, unsigned);

typedef void(mapi_alloc_tester_clean_fn)(struct mtf_test_info *);

int
mapi_alloc_tester(
    struct mtf_test_info *      lcl_ti,
    mapi_alloc_tester_run_fn *  run,
    mapi_alloc_tester_clean_fn *clean);

#endif
#endif
