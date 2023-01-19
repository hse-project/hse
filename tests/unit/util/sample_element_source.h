/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_SAMPLE_ELEMENT_SOURCE_H
#define HSE_PLATFORM_SAMPLE_ELEMENT_SOURCE_H

#include <stdint.h>

#include <hse/error/merr.h>
#include <hse/util/element_source.h>

enum sample_es_mode {
    SES_LINEAR = 0,    /* linear sequence of u32 0 to N-1 */
    SES_RANDOM = 1,    /* random sequence of u32 */
    SES_RANDOM_NR = 2, /* random sequence of u32, no repeats */
    SES_ONE = 3,       /* just this one element */
};

struct sample_es;

merr_t
sample_es_create(struct sample_es **es_out, uint32_t elt_cnt, enum sample_es_mode mode);

void
sample_es_set_elt(struct sample_es *es, uint32_t elt);

merr_t
sample_es_create_srcid(
    struct sample_es **es_out,
    uint32_t elt_cnt,
    uint32_t start,
    uint32_t srcid,
    enum sample_es_mode mode);

struct element_source *
sample_es_get_es_handle(struct sample_es *es);

void
sample_es_destroy(struct sample_es *es);

void
sample_es_sort(struct sample_es *es);

#endif
