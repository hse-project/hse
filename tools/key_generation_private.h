/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KEY_GENERATION_PRIVATE_H
#define HSE_KEY_GENERATION_PRIVATE_H

#include <hse_util/inttypes.h>

static char symbols[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                          'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                          'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

struct key_generator {
    u64   key_space_sz;
    s32   key_width;
    s32   field_width;
    s32   num_fields;
    s32   elem_per_field;
    char *elems;
};

s32
elements_per_field(u64 key_space_sz, s32 key_width, s32 field_width, s32 sym_cnt);

void
increment_multifield_index(s32 *index, s32 index_width, s32 wrap);

bool
generate_elements(char *elements, s32 width, s32 count);

#endif
