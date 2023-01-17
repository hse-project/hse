/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_MOCK_C0SK_H
#define HSE_CORE_MOCK_C0SK_H

#include <stdint.h>

#include <hse/error/merr.h>

#define INTEGRITY_CHECK 0xbe12face

struct c0sk;

struct mock_c0sk {
    int mczk_integrity;
    merr_t mczk_err;
    uint16_t mczk_skidx;
};

merr_t
create_mock_c0sk(struct c0sk **c0sk_out);

void
destroy_mock_c0sk(struct c0sk *c0sk);

#endif
