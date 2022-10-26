/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include "sample_element_source.h"

#include <hse/error/merr.h>
#include <hse/util/inttypes.h>
#include <hse/util/assert.h>

#include <support/random_buffer.h>

struct sample_es {
    u32 *                 tes_elts;
    u32                   tes_elt_cnt;
    u32                   tes_idx;
    struct element_source tes_handle;
};

#define sample_es_h2r(handle) container_of(handle, struct sample_es, tes_handle)

bool
sample_es_get_next(struct element_source *handle, void **item)
{
    struct sample_es *es = sample_es_h2r(handle);
    bool              res = true;

    if (es->tes_elt_cnt - es->tes_idx > 0)
        *item = (void *)&es->tes_elts[es->tes_idx++];
    else
        res = false;

    return res;
}

bool
sample_es_unget(struct element_source *handle)
{
    struct sample_es *es = sample_es_h2r(handle);

    if (es->tes_idx > 0)
        --es->tes_idx;
    return true;
}

merr_t
sample_es_create(struct sample_es **es_out, u32 elt_cnt, enum sample_es_mode mode)
{
    struct sample_es *es;
    size_t            sz;

    es = malloc(sizeof(*es));
    if (!es)
        return merr(ENOMEM);

    sz = elt_cnt * sizeof(u32);
    es->tes_elts = malloc(sz);
    if (!es->tes_elts) {
        free(es);
        return merr(ENOMEM);
    }
    es->tes_elt_cnt = elt_cnt;
    es->tes_idx = 0;

    if (mode == SES_LINEAR) {
        u32 i, start = generate_random_u32(0, 100000);

        for (i = 0; i < es->tes_elt_cnt; ++i)
            es->tes_elts[i] = start + i;
    } else if (mode == SES_RANDOM) {
        u32 min = generate_random_u32(0, 100000);
        u32 max = generate_random_u32(min, min + elt_cnt + 100000);

        generate_random_u32_sequence(min, max, es->tes_elts, es->tes_elt_cnt);
    } else if (mode == SES_ONE) {
        es->tes_elts[0] = elt_cnt;
        es->tes_elt_cnt = 1;
    } else {
        u32 i, j, start = generate_random_u32(0, 100000);

        assert(mode == SES_RANDOM_NR);
        for (i = 0, j = 0; i < es->tes_elt_cnt; ++i) {
            j += generate_random_u32(1, 100);
            es->tes_elts[i] = start + j;
        }
        permute_u32_sequence(es->tes_elts, es->tes_elt_cnt);
    }

    es->tes_handle = es_make(sample_es_get_next, sample_es_unget, 0);

    *es_out = es;

    return 0;
}

void
sample_es_set_elt(struct sample_es *es, u32 elt)
{
    es->tes_elts[0] = elt;
    es->tes_idx = 0; /* rewind - so es_get_next can get replacement */
}

merr_t
sample_es_create_srcid(
    struct sample_es ** es_out,
    u32                 elt_cnt,
    u32                 start,
    u32                 srcid,
    enum sample_es_mode mode)
{
    struct sample_es *es;
    size_t            sz;

    es = malloc(sizeof(*es));
    if (!es)
        return merr(ENOMEM);

    sz = elt_cnt * sizeof(u32);
    es->tes_elts = malloc(sz);
    if (!es->tes_elts) {
        free(es);
        return merr(ENOMEM);
    }
    es->tes_elt_cnt = elt_cnt;
    es->tes_idx = 0;

    if (mode == SES_LINEAR) {
        u32 i, first = start;

        for (i = 0; i < es->tes_elt_cnt; ++i)
            es->tes_elts[i] = (srcid << 24) + first + i;
    }

    es->tes_handle.es_get_next = sample_es_get_next;

    *es_out = es;

    return 0;
}

struct element_source *
sample_es_get_es_handle(struct sample_es *es)
{
    return &es->tes_handle;
}

void
sample_es_destroy(struct sample_es *es)
{
    free(es->tes_elts);
    free(es);
}

int
sample_es_cmp(const void *a, const void *b)
{
    const u32 a_val = *((u32 *)a);
    const u32 b_val = *((u32 *)b);

    if (a_val < b_val)
        return -1;
    else if (a_val > b_val)
        return 1;
    else
        return 0;
}

void
sample_es_sort(struct sample_es *es)
{
    qsort(es->tes_elts, es->tes_elt_cnt, sizeof(u32), sample_es_cmp);
}
