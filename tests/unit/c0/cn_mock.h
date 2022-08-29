/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CORE_MOCK_CN_H
#define HSE_CORE_MOCK_CN_H

#include <stdint.h>

struct cn;

merr_t
create_mock_cn(
    struct cn **cn_out,
    bool        delay_merge,
    bool        random_release,
    uint32_t    pfx_len);

void
destroy_mock_cn(struct cn *cn);

#endif
