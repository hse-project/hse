/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_TEST_MOCK_C1_H
#define HSE_KVDB_TEST_MOCK_C1_H

void
mock_c1_set(void);
void
mock_c1_unset(void);

void
mock_c0skm_set(void);
void
mock_c0skm_unset(void);

struct c0sk;
merr_t
create_mock_c0skm(struct c0sk *c0sk);
#endif
