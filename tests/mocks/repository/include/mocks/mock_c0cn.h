/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_TEST_MOCK_C0CN_H
#define HSE_KVDB_TEST_MOCK_C0CN_H

void
mock_kvdb_log_set(void);
void
mock_kvdb_log_unset(void);

void
mock_cndb_set(void);
void
mock_cndb_unset(void);

void
mock_cn_set(void);
void
mock_cn_unset(void);

void
mock_c0_set(void);
void
mock_c0_unset(void);

void
mock_c0cn_set(void);
void
mock_c0cn_unset(void);

void
mock_wal_set(void);
void
mock_wal_unset(void);

#endif
