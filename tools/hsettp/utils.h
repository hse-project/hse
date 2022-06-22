/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSETTP_UTILS_H
#define HSETTP_UTILS_H

#include <cjson/cJSON.h>

#include <hse/error/merr.h>

merr_t
flatten(cJSON *in, const char *prefix, cJSON *out);

char *
rawify(cJSON *node);

unsigned int
strchrrep(char *str, char old, char new);

#endif
