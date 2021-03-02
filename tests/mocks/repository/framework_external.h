/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

/*
 * Include this file in any mock implementation to have access to the
 * following symbols that get resolved at link time with invdividual test
 * executables.
 */

#ifndef HSE_MOCK_REPOSITORY_FRAMEWORK_EXTERNAL
#define HSE_MOCK_REPOSITORY_FRAMEWORK_EXTERNAL

extern const int   STATUS_CODE_LEN;
extern const char *FINAL_SUCCESS;
extern const char *PARTIAL_SUCCESS;

extern int         mtf_verify_flag;
extern int         mtf_verify_line;
extern const char *mtf_verify_file;

#endif
