/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2019 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSEJNI_INTERNAL_H
#define HSEJNI_INTERNAL_H

struct hse_params;

/**
 * jni_hse_params_parse() - Update members of params specified in the
 *                          comma separated param list
 * @params: The hse param instance to be updated
 * @p_list: comma separated list of param=value pairs
 */
int
jni_hse_params_parse(struct hse_params *params, const char *p_list);

/* Splits str into substrings at "/" */
int
split_str(char **substr1, char **substr2, char *str);

#endif /* HSEJNI_INTERNAL_H */
