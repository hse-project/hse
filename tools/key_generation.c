/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <tgmath.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <hse/tools/key_generation.h>

#include "key_generation_private.h"

int32_t
elements_per_field(uint64_t key_space_sz, int32_t key_width, int32_t field_width, int32_t sym_cnt)
{
    int32_t num_fields;
    int32_t partial_fw;
    int32_t num_epf;
    int64_t rem_kss;
    int64_t pf_el_lim;

    /* compute the # of fields needed */
    num_fields = (int32_t)ceil((double)key_width / (double)field_width);

    /* determine the width of the one possibly partial width field */
    partial_fw = key_width % field_width;

    /* compute minimum # of distinct elements per field */
    num_epf = (int32_t)ceil(pow((double)key_space_sz, 1.0 / num_fields));

    /* If there is a partial field, check to see if it can hold
     * the number of elements just computed.
     */
    pf_el_lim = (int64_t)pow(sym_cnt, partial_fw);
    if (partial_fw > 0 && (pf_el_lim < num_epf)) {
        rem_kss = (int64_t)ceil((double)key_space_sz / (double)pf_el_lim);
        num_epf = (int32_t)ceil(pow((double)rem_kss, 1.0 / (num_fields - 1)));
    }

    return num_epf;
}

void
increment_multifield_index(int32_t *index, int32_t index_width, int32_t wrap)
{
    int i;

    for (i = 0; i < index_width; ++i) {
        index[i] = (index[i] + 1) % wrap;
        if ((index[i] != 0) || (i == (index_width - 1)))
            return;
    }
}

bool
generate_elements(char *elements, int32_t width, int32_t count)
{
    int32_t  num_symbols = (int)ceil(pow((double)count, 1.0 / (double)width));
    int32_t *field_offsets;
    int      i, j;

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
create_key_generator(uint64_t key_space_sz, int32_t key_width)
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
    kg->num_fields = (int32_t)ceil((double)kg->key_width / (double)kg->field_width);

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
get_key(struct key_generator *self, uint8_t *key_buffer, uint64_t key_index)
{
    const int32_t epf = self->elem_per_field;
    const int32_t numf = self->num_fields;
    const int32_t kw = self->key_width;
    const int32_t fw = self->field_width;
    uint8_t *     pos = key_buffer + kw - fw;
    uint64_t      offset;
    int           i, copy_width;

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
