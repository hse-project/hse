/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef MOCKS_MOCK_C0CN_H
#define MOCKS_MOCK_C0CN_H

void
mock_kvdb_meta_set(void);
void
mock_kvdb_meta_unset(void);

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
