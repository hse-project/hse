/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/slab.h>

#include <hse_ut/framework.h>
#include <hse_test_support/random_buffer.h>

#include <hse_util/element_source.h>

#include "sample_element_source.h"

MTF_BEGIN_UTEST_COLLECTION(element_source_test);

MTF_DEFINE_UTEST(element_source_test, linear_sequence)
{
    struct sample_es *     es;
    u32 *                  last, *n;
    struct element_source *handle;
    merr_t                 err;

    err = sample_es_create(&es, 10, SES_LINEAR);
    ASSERT_FALSE(err);

    handle = sample_es_get_es_handle(es);

    ASSERT_TRUE(handle->es_get_next(handle, (void **)&n));

    last = n;
    while (handle->es_get_next(handle, (void *)&n)) {
        ASSERT_EQ(*last + 1, *n);
        last = n;
    }

    sample_es_destroy(es);
}

MTF_DEFINE_UTEST(element_source_test, random_sequence)
{
    struct sample_es *     es;
    int                    count;
    struct element_source *handle;
    merr_t                 err;
    u32 *                  n;
    const int              COUNT = 173;

    err = sample_es_create(&es, COUNT, SES_RANDOM);
    ASSERT_FALSE(err);

    handle = sample_es_get_es_handle(es);

    count = 0;
    while (handle->es_get_next(handle, (void *)&n))
        ++count;

    ASSERT_EQ(COUNT, count);

    sample_es_destroy(es);
}

MTF_DEFINE_UTEST(element_source_test, random_nr_sequence)
{
    struct sample_es *     es;
    int                    count;
    struct element_source *handle;
    merr_t                 err;
    u32 *                  n;
    const int              COUNT = 173;

    err = sample_es_create(&es, COUNT, SES_RANDOM_NR);
    ASSERT_FALSE(err);

    handle = sample_es_get_es_handle(es);

    count = 0;
    while (handle->es_get_next(handle, (void *)&n))
        ++count;

    ASSERT_EQ(COUNT, count);

    sample_es_destroy(es);
}

MTF_DEFINE_UTEST(element_source_test, empty_sequence)
{
    struct sample_es *     es;
    int                    count;
    struct element_source *handle;
    merr_t                 err;
    u32 *                  n;
    const int              COUNT = 0;

    err = sample_es_create(&es, COUNT, SES_LINEAR);
    ASSERT_FALSE(err);

    handle = sample_es_get_es_handle(es);

    count = 0;
    while (handle->es_get_next(handle, (void *)&n))
        ++count;

    ASSERT_EQ(COUNT, count);

    sample_es_destroy(es);
}

MTF_END_UTEST_COLLECTION(element_source_test)
