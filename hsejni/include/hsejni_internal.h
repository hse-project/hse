/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019,2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSEJNI_INTERNAL_H
#define HSEJNI_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

/**
 * jni_hse_config_parse() - Update members of config specified in the
 *                          comma separated config list
 */
int
jni_hse_config_parse(size_t *argc, const char **argv, char *p_list, const char *prefix, uint32_t max_args);

#endif /* HSEJNI_INTERNAL_H */
