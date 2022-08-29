/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <stdlib.h>

#include "sample_element_source.h"

#include <hse/error/merr.h>
#include <hse/util/assert.h>
#include <hse/util/base.h>

#include <hse/test/support/random_buffer.h>

struct sample_es {
    uint32_t *            tes_elts;
    uint32_t              tes_elt_cnt;
    uint32_t              tes_idx;
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
sample_es_create(struct sample_es **es_out, uint32_t elt_cnt, enum sample_es_mode mode)
{
    struct sample_es *es;
    size_t            sz;

    es = malloc(sizeof(*es));
    if (!es)
        return merr(ENOMEM);

    sz = elt_cnt * sizeof(uint32_t);
    es->tes_elts = malloc(sz);
    if (!es->tes_elts) {
        free(es);
        return merr(ENOMEM);
    }
    es->tes_elt_cnt = elt_cnt;
    es->tes_idx = 0;

    if (mode == SES_LINEAR) {
        uint32_t i, start = generate_random_u32(0, 100000);

        for (i = 0; i < es->tes_elt_cnt; ++i)
            es->tes_elts[i] = start + i;
    } else if (mode == SES_RANDOM) {
        uint32_t min = generate_random_u32(0, 100000);
        uint32_t max = generate_random_u32(min, min + elt_cnt + 100000);

        generate_random_u32_sequence(min, max, es->tes_elts, es->tes_elt_cnt);
    } else if (mode == SES_ONE) {
        es->tes_elts[0] = elt_cnt;
        es->tes_elt_cnt = 1;
    } else {
        uint32_t i, j, start = generate_random_u32(0, 100000);

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
sample_es_set_elt(struct sample_es *es, uint32_t elt)
{
    es->tes_elts[0] = elt;
    es->tes_idx = 0; /* rewind - so es_get_next can get replacement */
}

merr_t
sample_es_create_srcid(
    struct sample_es ** es_out,
    uint32_t            elt_cnt,
    uint32_t            start,
    uint32_t            srcid,
    enum sample_es_mode mode)
{
    struct sample_es *es;
    size_t            sz;

    es = malloc(sizeof(*es));
    if (!es)
        return merr(ENOMEM);

    sz = elt_cnt * sizeof(uint32_t);
    es->tes_elts = malloc(sz);
    if (!es->tes_elts) {
        free(es);
        return merr(ENOMEM);
    }
    es->tes_elt_cnt = elt_cnt;
    es->tes_idx = 0;

    if (mode == SES_LINEAR) {
        uint32_t i, first = start;

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
    const uint32_t a_val = *((uint32_t *)a);
    const uint32_t b_val = *((uint32_t *)b);

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
    qsort(es->tes_elts, es->tes_elt_cnt, sizeof(uint32_t), sample_es_cmp);
}
