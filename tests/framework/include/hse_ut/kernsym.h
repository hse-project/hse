/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc. All rights reserved.
 */
#ifndef HSE_UTEST_KERNSYM_H
#define HSE_UTEST_KERNSYM_H

#if defined(HSE_UNIT_TEST_MODE) && HSE_UNIT_TEST_MODE != 0
#define HSE_UT_EXPORT_SYMBOL(_sym) EXPORT_SYMBOL(_sym)
#else
#define HSE_UT_EXPORT_SYMBOL(_sym)
#endif

#endif /* HSE_UTEST_KERNSYM_H */
