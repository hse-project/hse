/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_CORE_MOCK_CN_H
#define HSE_CORE_MOCK_CN_H

#include <stdbool.h>
#include <stdint.h>

#include <hse/error/merr.h>

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
