/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2017,2022 Micron Technology, Inc.  All rights reserved.
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <hse/util/inttypes.h>
#include <tools/key_generation.h>

#include "key_generation_private.h"

s32
elements_per_field(u64 key_space_sz, s32 key_width, s32 field_width, s32 sym_cnt)
{
    s32 num_fields;
    s32 partial_fw;
    s32 num_epf;
    s64 rem_kss;
    s64 pf_el_lim;

    /* compute the # of fields needed */
    num_fields = (s32)ceil((double)key_width / (double)field_width);

    /* determine the width of the one possibly partial width field */
    partial_fw = key_width % field_width;

    /* compute minimum # of distinct elements per field */
    num_epf = (s32)ceil(pow((double)key_space_sz, 1.0 / num_fields));

    /* If there is a partial field, check to see if it can hold
     * the number of elements just computed.
     */
    pf_el_lim = (s64)pow(sym_cnt, partial_fw);
    if (partial_fw > 0 && (pf_el_lim < num_epf)) {
        rem_kss = (s64)ceil((double)key_space_sz / (double)pf_el_lim);
        num_epf = (s32)ceil(pow((double)rem_kss, 1.0 / (num_fields - 1)));
    }

    return num_epf;
}

void
increment_multifield_index(s32 *index, s32 index_width, s32 wrap)
{
    int i;

    for (i = 0; i < index_width; ++i) {
        index[i] = (index[i] + 1) % wrap;
        if ((index[i] != 0) || (i == (index_width - 1)))
            return;
    }
}

bool
generate_elements(char *elements, s32 width, s32 count)
{
    s32    num_symbols = (int)ceil(pow((double)count, 1.0 / (double)width));
    s32 *  field_offsets;
    int    i, j;

    field_offsets = calloc(1, width * sizeof(*field_offsets));
    if (!field_offsets)
        return false;

    for (i = 0; i < count; ++i) {
        for (j = 0; j < width; ++j) {
            elements[i * width + (width - 1) - j] = symbols[field_offsets[j]];
        }
        increment_multifield_index(field_offsets, width, num_symbols);
    }

    free(field_offsets);

    return true;
}

struct key_generator *
create_key_generator(u64 key_space_sz, s32 key_width)
{
    struct key_generator *kg;
    double                tmp;

    /* can't have 0 or negative width keys */
    if (key_width <= 0)
        return 0;

    /* key width must support requested key space size */
    {
        double key_width_span;
        double x = (double)sizeof(symbols);
        double y = (double)key_width;

        tmp = pow(x, y);
        key_width_span = ceil(tmp);
        if (key_width_span < (double)key_space_sz)
            return 0;
    }

    kg = calloc(1, sizeof(*kg));
    if (kg == 0)
        return 0;

    kg->key_space_sz = key_space_sz;
    kg->key_width = key_width;
    kg->field_width = 4;
    kg->num_fields = (s32)ceil((double)kg->key_width / (double)kg->field_width);

    kg->elem_per_field =
        elements_per_field(kg->key_space_sz, kg->key_width, kg->field_width, sizeof(symbols));
    kg->elems = malloc(kg->elem_per_field * kg->field_width);
    if (kg->elems == 0) {
        free(kg);
        return 0;
    }

    generate_elements(kg->elems, kg->field_width, kg->elem_per_field);

    return kg;
}

void
destroy_key_generator(struct key_generator *kg)
{
    if (kg) {
        free(kg->elems);
        free(kg);
    }
}

void
get_key(struct key_generator *self, u8 *key_buffer, u64 key_index)
{
    const s32 epf = self->elem_per_field;
    const s32 numf = self->num_fields;
    const s32 kw = self->key_width;
    const s32 fw = self->field_width;
    u8 *      pos = key_buffer + kw - fw;
    u64       offset;
    int       i, copy_width;

    copy_width = fw;

    for (i = 0; i < (numf - 1); ++i) {
        offset = fw * (key_index % epf);
        key_index /= epf;
        memcpy(pos, self->elems + offset, copy_width);
        pos -= copy_width;
    }
    offset = fw * (key_index % epf);
    if ((kw % fw) != 0) {
        copy_width = (kw % fw);
        pos += (fw - (kw % fw));
        offset += (fw - (kw % fw));
    }
    memcpy(pos, self->elems + offset, copy_width);
}
