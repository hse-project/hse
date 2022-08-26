/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_CONFIG_LOGGING_H
#define HSE_CONFIG_LOGGING_H

struct params;

const char *
params_logging_context(const struct params *const p);

#endif
