/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef HSE_KEY_GENERATION_PRIVATE_H
#define HSE_KEY_GENERATION_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static char symbols[] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
                          'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                          'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };

struct key_generator {
    size_t key_space_sz;
    size_t key_width;
    size_t field_width;
    int32_t num_fields;
    int32_t elem_per_field;
    char *elems;
};

int32_t
elements_per_field(uint64_t key_space_sz, int32_t key_width, int32_t field_width, int32_t sym_cnt);

void
increment_multifield_index(int32_t *index, int32_t index_width, int32_t wrap);

bool
generate_elements(char *elements, int32_t width, int32_t count);

#endif
