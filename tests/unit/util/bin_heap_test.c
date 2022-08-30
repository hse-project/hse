/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <mock/api.h>
#include <mtf/framework.h>

#include <hse/logging/logging.h>
#include <hse_util/bin_heap.h>
#include <hse_util/element_source.h>
#include <hse_util/xrand.h>

#include "sample_element_source.h"

MTF_BEGIN_UTEST_COLLECTION(bin_heap_test);

int
u32_cmp(const void *a, const void *b)
{
    const u32 a_val = *((u32 *)a);
    const u32 b_val = *((u32 *)b);

    return a_val - b_val;
}

int
ks_cmp(const void *a, const void *b)
{
    const u32 *a_val = a;
    const u32 *b_val = b;

    return (*a_val & 0xffffff) - (*b_val & 0xffffff);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_creation)
{
    const u32 WIDTH = 17;

    struct bin_heap *bh;
    merr_t            err;

    err = bin_heap_create(WIDTH, u32_cmp, &bh);
    ASSERT_EQ(0, err);
    bin_heap_destroy(bh);

    err = bin_heap_create(0, u32_cmp, &bh);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = bin_heap_create(WIDTH, 0, &bh);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = bin_heap_create(WIDTH, u32_cmp, 0);
    ASSERT_EQ(merr_errno(err), EINVAL);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, 0);
    err = bin_heap_create(WIDTH, u32_cmp, &bh);
    mapi_inject_unset(mapi_idx_malloc);
    ASSERT_EQ(merr_errno(err), ENOMEM);

    bin_heap_destroy(0);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_one)
{
    const u32  WIDTH = 7;
    const char set[] = "XAQBTCM";
    const char ordered[] = "ABCMQTX";

    struct bin_heap *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH];
    char                   out[WIDTH];
    merr_t                 err;
    int                    i;
    void *                 item = NULL;
    u32                    v, last;

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], set[i], SES_ONE);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    bin_heap_create(WIDTH, u32_cmp, &bh);
    bin_heap_prepare(bh, WIDTH, handles);

    for (i = 0, last = 0; bin_heap_pop(bh, &item); last = v) {
        v = *(u32 *)item;
        ASSERT_LE(last, v);
        printf("%c ", v);
        out[i++] = v;
    }
    printf("\n");

    ASSERT_EQ(0, strncmp(ordered, out, WIDTH));
    bin_heap_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_insert_remove)
{
    const u32  WIDTH = 7;
    const char set[] = "XAQBTCM";
    const char ordered[] = "ABCMQTX";

    struct bin_heap *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH + 1];
    char                   out[WIDTH];
    merr_t                 err;
    int                    i, j;
    void *                 item = NULL;
    u32                    v, last;

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], set[i], SES_ONE);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    bin_heap_create(WIDTH, u32_cmp, &bh);
    bin_heap_prepare(bh, 1, handles);

    last = -1;
    for (i = 1; i < WIDTH; ++i) {
        err = bin_heap_insert_src(bh, handles[i]);
        ASSERT_EQ(0, err);
        bin_heap_peek(bh, &item);
        v = *(u32 *)item;
        ASSERT_LE(v, last);
        last = v;
    }

    for (i = 0, last = 0; bin_heap_pop(bh, &item); last = v) {
        v = *(u32 *)item;
        ASSERT_LE(last, v);
        printf("%c ", v);
        ASSERT_LE(i, WIDTH);
        out[i++] = v;
    }
    printf("\n");
    ASSERT_EQ(0, strncmp(ordered, out, WIDTH));

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    /*
     * rm each item - verify order remains correct
     */
    for (j = 0; j < WIDTH; ++j) {
        memset(handles, 0, sizeof(handles));
        for (i = 0; i < WIDTH; ++i) {
            err = sample_es_create(&es[i], set[i], SES_ONE);
            ASSERT_EQ(0, err);
            handles[i] = sample_es_get_es_handle(es[i]);
        }
        for (i = 0; i < WIDTH; ++i)
            handles[i]->es_next_src = handles[i + 1];
        bin_heap_prepare_list(bh, WIDTH, handles[0]);
        bin_heap_remove_src(bh, handles[j], true);

        printf("removed %c: ", set[j]);
        for (i = 0, last = 0; bin_heap_pop(bh, &item); last = v) {
            v = *(u32 *)item;
            ASSERT_LE(last, v);
            printf("%c ", v);
            last = v;
        }
        printf("\n");

        for (i = 0; i < WIDTH; ++i)
            sample_es_destroy(es[i]);
    }

    bin_heap_reset(bh);
    memset(handles, 0, sizeof(handles));
    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], set[i], SES_ONE);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }
    bin_heap_prepare(bh, WIDTH, handles);
    bin_heap_pop(bh, &item);
    ASSERT_NE(0, item);
    bin_heap_remove_all(bh);
    bin_heap_pop(bh, &item);
    ASSERT_EQ(0, item);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    bin_heap_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_replace_test)
{
    const u32 WIDTH = 7;
    char      set[] = "XBQCTDM";
    char *    expected;

    struct bin_heap *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH + 1];
    merr_t                 err;
    int                    i, j;
    void *                 item = NULL;
    u32                    v;

    bin_heap_create(WIDTH, u32_cmp, &bh);

    for (j = 0; j < WIDTH; ++j) {
        memset(handles, 0, sizeof(handles));
        for (i = 0; i < WIDTH; ++i) {
            err = sample_es_create(&es[i], set[i], SES_ONE);
            ASSERT_EQ(0, err);
            handles[i] = sample_es_get_es_handle(es[i]);
        }
        bin_heap_prepare(bh, WIDTH, handles);

        sample_es_set_elt(es[j], 'A');
        bin_heap_replace_src(bh, handles[j]);
        printf("replaced %c with %c\n", set[j], 'A');
        bin_heap_pop(bh, &item);
        v = *(u32 *)item;
        ASSERT_EQ('A', v);
        sample_es_set_elt(es[j], set[j]);

        for (i = 0; i < WIDTH; ++i)
            sample_es_destroy(es[i]);
    }

    for (j = 0; j < WIDTH; ++j) {
        memset(handles, 0, sizeof(handles));
        for (i = 0; i < WIDTH; ++i) {
            err = sample_es_create(&es[i], set[i], SES_ONE);
            ASSERT_EQ(0, err);
            handles[i] = sample_es_get_es_handle(es[i]);
        }
        bin_heap_prepare(bh, WIDTH, handles);

        sample_es_set_elt(es[j], 'E');
        bin_heap_replace_src(bh, handles[j]);
        printf("replaced %c with %c\n", set[j], 'E');
        bin_heap_pop(bh, &item);
        bin_heap_pop(bh, &item);
        bin_heap_pop(bh, &item);
        if (set[j] > 'E')
            bin_heap_pop(bh, &item);

        v = *(u32 *)item;
        ASSERT_EQ('E', v);
        sample_es_set_elt(es[j], set[j]);

        for (i = 0; i < WIDTH; ++i)
            sample_es_destroy(es[i]);
    }

    memset(handles, 0, sizeof(handles));
    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], set[i], SES_ONE);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }
    bin_heap_prepare(bh, WIDTH, handles);

    /* replace second half */
    for (i = WIDTH / 2; i < WIDTH; i++) {
        sample_es_set_elt(es[i], 'F' + i);
        bin_heap_replace_src(bh, handles[i]);
    }

    expected = "BIJKLQX";
    printf("replaced %s with %s\n", set, expected);
    for (i = 0; i < WIDTH; i++) {
        bin_heap_pop(bh, &item);
        v = *(u32 *)item;
        ASSERT_EQ(expected[i], v);
    }

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    bin_heap_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_basic)
{
    const u32 WIDTH = 17;

    struct bin_heap *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH];
    merr_t                 err;
    int                    i;
    void *                 item = NULL;
    u32                    value, last;

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], 1123, SES_LINEAR);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    bin_heap_create(WIDTH, u32_cmp, &bh);

    bin_heap_prepare(bh, WIDTH, handles);

    bin_heap_pop(bh, &item);
    last = *(u32 *)item;

    while (bin_heap_pop(bh, &item)) {
        value = *(u32 *)item;
        ASSERT_LE(last, value);
        last = value;
    }

    bin_heap_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], 1123, SES_RANDOM);
        ASSERT_EQ(0, err);
        sample_es_sort(es[i]);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    bin_heap_create(WIDTH, u32_cmp, &bh);

    bin_heap_prepare(bh, WIDTH, handles);

    bin_heap_pop(bh, &item);
    last = *(u32 *)item;

    while (bin_heap_pop(bh, &item)) {
        value = *(u32 *)item;
        ASSERT_LE(last, value);
        last = value;
    }

    bin_heap_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

#define getval(x) (*(x)&0xffffff)
#define getsrc(x) (*(x) >> 24)

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_dups)
{
    const u32 WIDTH = 3;

    struct bin_heap *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH];
    u32 *                  item = NULL, *dup = NULL;
    merr_t                 err;
    int                    i;
    u32                    last, src;

    /* create sample es's with identical keys, differing srcids */
    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create_srcid(&es[i], 1123, 0, i, SES_LINEAR);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    err = bin_heap_create(WIDTH, ks_cmp, &bh);
    ASSERT_EQ(0, err);

    bin_heap_prepare(bh, WIDTH, handles);

    bin_heap_pop(bh, (void **)&item);
    src = getsrc(item);
    last = getval(item);
    ASSERT_EQ(0, src);

    /* suppress dups */
    while (bin_heap_peek(bh, (void **)&dup)) {
        if (getval(dup) != last)
            break;
        ASSERT_LT(src, getsrc(dup));
        bin_heap_pop(bh, (void **)&dup);
    }

    while (bin_heap_pop(bh, (void **)&item)) {
        ASSERT_LE(last, getval(item));
        ASSERT_EQ(0, getsrc(item));
        last = getval(item);

        /* suppress dups */
        while (bin_heap_peek(bh, (void **)&dup)) {
            if (getval(dup) != last)
                break;
            ASSERT_LT(src, getsrc(dup));
            bin_heap_pop(bh, (void **)&dup);
        }
    }

    bin_heap_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_usage_error)
{
    const u32 WIDTH = 17;

    struct bin_heap *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH];
    merr_t                 err;
    int                    i;

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], 1123, SES_LINEAR);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    err = bin_heap_create(WIDTH - 1, u32_cmp, &bh);
    ASSERT_EQ(0, err);

    err = bin_heap_prepare(bh, WIDTH, handles);
    ASSERT_EQ(merr_errno(err), EOVERFLOW);

    bin_heap_destroy(bh);

    err = bin_heap_create(WIDTH, u32_cmp, &bh);
    ASSERT_EQ(0, err);
    err = bin_heap_prepare(bh, WIDTH, handles);
    ASSERT_EQ(0, err);

    bin_heap_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap_age_cmp_test)
{
    struct element_source e1, e2;
    int                   rc;

    e1.es_sort = 10;
    e2.es_sort = 12;

    rc = bin_heap_age_cmp(&e1, &e2);
    ASSERT_EQ(-2, rc);
}

MTF_END_UTEST_COLLECTION(bin_heap_test)
