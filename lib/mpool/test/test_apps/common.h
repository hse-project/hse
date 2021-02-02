/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */


#ifndef MPOOL_TEST_COMMON_H
#define MPOOL_TEST_COMMON_H

extern uint8_t *pattern;
extern uint32_t pattern_len;

int pattern_base(char *base);

void pattern_fill(char *buf, uint32_t buf_sz);

int pattern_compare(char *buf, uint32_t buf_sz);

#endif /* MPOOL_TEST_COMMON_H */
