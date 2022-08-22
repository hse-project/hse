/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/logging/logging.h>
#include <hse_util/xrand.h>
#include <hse_util/bin_heap.h>
#include <hse_util/element_source.h>

#include "sample_element_source.h"

const char *TestKey[] = { "abc000", "abc001", "abc002", "abc003" };
const char *TestKeyBogus = "xyz000";

int
minheap_compare_strp(const void *pkey1, const void *pkey2)
{
    return strcmp(*(const char **)pkey1, *(const char **)pkey2);
}

int
maxheap_compare_strp(const void *pkey1, const void *pkey2)
{
    return -strcmp(*(const char **)pkey1, *(const char **)pkey2);
}

int
minheap_compare_u64(const void *a, const void *b)
{
    const unsigned long *x = (const unsigned long *)a;
    const unsigned long *y = (const unsigned long *)b;

    return *x < *y ? -1 : 0;
}

#define putkey(KEY) _putkey(lcl_ti, bh, KEY)
#define delkey(KEY) _delkey(lcl_ti, bh, KEY)
#define getkey(KEY) _getkey(lcl_ti, bh, KEY)

void
_putkey(struct mtf_test_info *lcl_ti, struct bin_heap *bh, int key)
{
    merr_t err;

    err = bin_heap_insert(bh, &TestKey[key]);
    ASSERT_FALSE(err);
}

void
_delkey(struct mtf_test_info *lcl_ti, struct bin_heap *bh, int key)
{
    bool        found;
    const char *item = TestKeyBogus;

    found = bin_heap_get_delete(bh, &item);
    ASSERT_TRUE(found);
    ASSERT_EQ(0, strcmp(item, TestKey[key]));
}

void
_getkey(struct mtf_test_info *lcl_ti, struct bin_heap *bh, int key)
{
    bool        found;
    const char *item = TestKeyBogus;

    found = bin_heap_get(bh, &item);
    ASSERT_TRUE(found);
    ASSERT_EQ(0, strcmp(item, TestKey[key]));
}

int
test_collection_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(bin_heap_test, test_collection_pre);

MTF_DEFINE_UTEST(bin_heap_test, Create)
{
    struct bin_heap *bh;
    merr_t           err;
    int              i;

    u32 max_items = 10;
    s32 sizes[] = { 1, 2, 3, 4, 10, 20, 100, 1000 };

    for (i = 0; i < NELEM(sizes); i++) {
        err = bin_heap_create(&bh, max_items, sizes[i], minheap_compare_strp);
        ASSERT_FALSE(err);
        ASSERT_TRUE(bh);
        bin_heap_check(bh);
        bin_heap_destroy(bh);
    }
}

MTF_DEFINE_UTEST(bin_heap_test, CreateFail1)
{
    struct bin_heap *bh;
    merr_t           err;

    err = bin_heap_create(&bh, 10, 4, NULL);
    ASSERT_TRUE(err);

    err = bin_heap_create(&bh, 10, 0, minheap_compare_strp);
    ASSERT_TRUE(err);

    err = bin_heap_create(&bh, 0, 4, minheap_compare_strp);
    ASSERT_TRUE(err);

    err = bin_heap_create(NULL, 10, 4, minheap_compare_strp);
    ASSERT_TRUE(err);
}

MTF_DEFINE_UTEST(bin_heap_test, CreateDeleteEmpty)
{
    struct bin_heap *bh;
    merr_t           err;
    bool             found;
    int              item;

    err = bin_heap_create(&bh, 10, sizeof(item), minheap_compare_strp);
    ASSERT_FALSE(err);
    ASSERT_TRUE(bh);

    found = bin_heap_get(bh, &item);
    ASSERT_FALSE(found);

    found = bin_heap_get_delete(bh, &item);
    ASSERT_FALSE(found);

    bin_heap_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, Add)
{
    struct bin_heap *bh;
    merr_t           err;
    bool             found;

    err = bin_heap_create(&bh, 10, sizeof(char *), minheap_compare_strp);
    ASSERT_FALSE(err);
    ASSERT_TRUE(bh);

    putkey(0);

    /* should all succeed */
    getkey(0);
    getkey(0);
    delkey(0);

    /* should fail */
    const char *item = TestKeyBogus;

    found = bin_heap_get(bh, &item);
    ASSERT_FALSE(found);

    bin_heap_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, MinHeap)
{
    struct bin_heap *bh;
    merr_t           err;

    err = bin_heap_create(&bh, 10, sizeof(char *), minheap_compare_strp);
    ASSERT_FALSE(err);
    ASSERT_TRUE(bh);

    putkey(2);
    putkey(3);
    putkey(0);
    putkey(1);

    delkey(0);
    delkey(1);
    delkey(2);
    delkey(3);

    bin_heap_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, MaxHeap)
{
    struct bin_heap *bh;
    merr_t           err;

    err = bin_heap_create(&bh, 10, sizeof(char *), maxheap_compare_strp);
    ASSERT_FALSE(err);
    ASSERT_TRUE(bh);

    putkey(2);
    putkey(3);
    putkey(0);
    putkey(1);

    delkey(3);
    delkey(2);
    delkey(1);
    delkey(0);

    bin_heap_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, MinHeapWithDuplicates)
{
    struct bin_heap *bh;
    merr_t           err;

    err = bin_heap_create(&bh, 10, sizeof(char *), minheap_compare_strp);
    ASSERT_FALSE(err);
    ASSERT_TRUE(bh);

    putkey(1);
    putkey(2);
    putkey(1);
    putkey(3);
    putkey(1);
    putkey(0);
    putkey(1);

    delkey(0);

    delkey(1);
    delkey(1);
    delkey(1);
    delkey(1);

    delkey(2);
    delkey(3);

    bin_heap_destroy(bh);
}

struct test_params {
    u64 count;
    u64 seed;
};

struct test {
    struct mtf_test_info *mtf;
    struct test_params    p;
    struct bin_heap *     bh;
    u64 *                 input_items;
    u64                   inserted, deleted;
    int                   show_puts;
};

static void
insert_next(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;
    merr_t                err;
    u64                   item;

    ASSERT_TRUE(t->inserted < t->p.count);
    item = t->input_items[t->inserted];

    if (t->show_puts) {
        if (t->inserted < 20)
            log_info("put %12lu", item);
        else if (t->inserted == 20)
            log_info("put ...");
    }
    err = bin_heap_insert(t->bh, &item);
    ASSERT_FALSE(err);
    t->inserted++;
}

static void delete (struct test *t, u64 expected)
{
    struct mtf_test_info *lcl_ti = t->mtf;
    u64                   item = (u64)-1;
    bool                  found;

    found = bin_heap_get_delete(t->bh, &item);
    ASSERT_TRUE(found);
    ASSERT_EQ(item, expected);
    t->deleted++;
}

static void
delete_nocheck(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;
    u64                   item = (u64)-1;
    bool                  found;

    found = bin_heap_get_delete(t->bh, &item);
    ASSERT_TRUE(found);
    t->deleted++;
}

static void
UpDown(struct test *t)
{
    int i;

    for (i = 0; i < t->p.count; i++)
        insert_next(t);

    for (i = 0; i < t->p.count; i++)
        delete (t, i);
}

static void
UpAroundDown(struct test *t)
{
    struct mtf_test_info *lcl_ti = t->mtf;
    u64                   N = t->p.count;
    u64                   ins_tot = 0;
    u64                   del_tot = 0;
    u64                   icnt, dcnt;
    u64                   salt = 0;
    u64                   i;

    t->show_puts = 0;

    while (ins_tot < N || del_tot < N) {

        salt += N * 17 + 123457;

        /* figure out how many insert and delete on this iteration */
        ASSERT_TRUE(del_tot <= ins_tot);

        if (ins_tot < N) {
            icnt = (N / 20) + (salt % 20);
            if (!icnt)
                ++icnt;
            if (icnt + ins_tot > N)
                icnt = N - ins_tot;

            /* sanity checks */
            ASSERT_TRUE(icnt > 0);

            dcnt = (ins_tot + icnt - del_tot) / (1 + (salt % 9));
            if (!dcnt)
                ++dcnt;
            if (dcnt > ins_tot + icnt - del_tot)
                dcnt = ins_tot + icnt - del_tot;

            ASSERT_TRUE(dcnt > 0);
        } else {
            /* no more inserts.  delet all remaining */
            icnt = 0;
            dcnt = ins_tot - del_tot;
        }

        log_info("add %lu (cursor=%lu); del %lu (cursor=%lu)",
                 icnt, icnt + ins_tot,
                 dcnt, dcnt + del_tot);

        for (i = 0; i < icnt; i++)
            insert_next(t);

        for (i = 0; i < dcnt; i++)
            delete_nocheck(t);

        ins_tot += icnt;
        del_tot += dcnt;
    }

    ASSERT_EQ(t->deleted, t->inserted);

    /* test empty */
    {
        u64  item = 99;
        bool found = bin_heap_get_delete(t->bh, &item);

        ASSERT_FALSE(found);
    }
}

static void
test_init(struct test *t, struct test_params *params, struct mtf_test_info *lcl_ti)
{
    struct xrand xr;
    u64             i, j, tmp;
    merr_t          err;

    memset(t, 0, sizeof(*t));
    t->p = *params;
    t->mtf = lcl_ti;
    t->show_puts = 1;

    err = bin_heap_create(&t->bh, t->p.count, sizeof(u64), minheap_compare_u64);
    ASSERT_FALSE(err);
    ASSERT_TRUE(t->bh);

    ASSERT_TRUE(t->p.count > 0);

    t->input_items = malloc(t->p.count * sizeof(*t->input_items));
    ASSERT_TRUE(t->input_items != NULL);

    for (i = 0; i < t->p.count; i++)
        t->input_items[i] = i;

    if (t->p.count > 0) {
        /* Knuth shuffle */
        xrand_init(&xr, t->p.seed);
        for (i = t->p.count - 1; i > 0; i--) {
            /* use mod (weak randomness is okay) */
            j = xrand64(&xr) % (i + 1);
            tmp = t->input_items[i];
            t->input_items[i] = t->input_items[j];
            t->input_items[j] = tmp;
        }
    }
}

static void
test_fini(struct test *t)
{
    bin_heap_destroy(t->bh);
    free(t->input_items);
}

#define MY_DEFINE_TEST(NAME, N1, V1, N2, V2)                                       \
    MTF_DEFINE_UTEST(bin_heap_test, NAME##_##N1##V1##_##N2##V2)                    \
    {                                                                              \
        struct test_params tp = {                                                  \
            .N1 = V1, .N2 = V2,                                                    \
        };                                                                         \
        struct test test;                                                          \
                                                                                   \
        log_info("Test %s(seed=%lu count=%lu)", #NAME, tp.seed, tp.count);         \
        test_init(&test, &tp, lcl_ti);                                             \
        NAME(&test);                                                               \
        test_fini(&test);                                                          \
    }

#define MY_TEST(N1, V1, N2, V2)            \
    MY_DEFINE_TEST(UpDown, N1, V1, N2, V2) \
    MY_DEFINE_TEST(UpAroundDown, N1, V1, N2, V2)

MY_TEST(count, 15, seed, 1);
MY_TEST(count, 15, seed, 2);
MY_TEST(count, 15, seed, 3);

MY_TEST(count, 16, seed, 1);
MY_TEST(count, 16, seed, 2);
MY_TEST(count, 16, seed, 3);

MY_TEST(count, 17, seed, 1);
MY_TEST(count, 17, seed, 2);
MY_TEST(count, 17, seed, 3);

MY_TEST(count, 100, seed, 1);
MY_TEST(count, 1000, seed, 2);
MY_TEST(count, 10000, seed, 3);

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

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_creation)
{
    const u32 WIDTH = 17;

    struct bin_heap2 *bh;
    merr_t            err;

    err = bin_heap2_create(WIDTH, u32_cmp, &bh);
    ASSERT_EQ(0, err);
    bin_heap2_destroy(bh);

    err = bin_heap2_create(0, u32_cmp, &bh);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = bin_heap2_create(WIDTH, 0, &bh);
    ASSERT_EQ(merr_errno(err), EINVAL);

    err = bin_heap2_create(WIDTH, u32_cmp, 0);
    ASSERT_EQ(merr_errno(err), EINVAL);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, 0);
    err = bin_heap2_create(WIDTH, u32_cmp, &bh);
    mapi_inject_unset(mapi_idx_malloc);
    ASSERT_EQ(merr_errno(err), ENOMEM);

    bin_heap2_destroy(0);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_one)
{
    const u32  WIDTH = 7;
    const char set[] = "XAQBTCM";
    const char ordered[] = "ABCMQTX";

    struct bin_heap2 *     bh;
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

    bin_heap2_create(WIDTH, u32_cmp, &bh);
    bin_heap2_prepare(bh, WIDTH, handles);

    for (i = 0, last = 0; bin_heap2_pop(bh, &item); last = v) {
        v = *(u32 *)item;
        ASSERT_LE(last, v);
        printf("%c ", v);
        out[i++] = v;
    }
    printf("\n");

    ASSERT_EQ(0, strncmp(ordered, out, WIDTH));
    bin_heap2_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_insert_remove)
{
    const u32  WIDTH = 7;
    const char set[] = "XAQBTCM";
    const char ordered[] = "ABCMQTX";

    struct bin_heap2 *     bh;
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

    bin_heap2_create(WIDTH, u32_cmp, &bh);
    bin_heap2_prepare(bh, 1, handles);

    last = -1;
    for (i = 1; i < WIDTH; ++i) {
        err = bin_heap2_insert_src(bh, handles[i]);
        ASSERT_EQ(0, err);
        bin_heap2_peek(bh, &item);
        v = *(u32 *)item;
        ASSERT_LE(v, last);
        last = v;
    }

    for (i = 0, last = 0; bin_heap2_pop(bh, &item); last = v) {
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
        bin_heap2_prepare_list(bh, WIDTH, handles[0]);
        bin_heap2_remove_src(bh, handles[j], true);

        printf("removed %c: ", set[j]);
        for (i = 0, last = 0; bin_heap2_pop(bh, &item); last = v) {
            v = *(u32 *)item;
            ASSERT_LE(last, v);
            printf("%c ", v);
            last = v;
        }
        printf("\n");

        for (i = 0; i < WIDTH; ++i)
            sample_es_destroy(es[i]);
    }

    bin_heap2_reset(bh);
    memset(handles, 0, sizeof(handles));
    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], set[i], SES_ONE);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }
    bin_heap2_prepare(bh, WIDTH, handles);
    bin_heap2_pop(bh, &item);
    ASSERT_NE(0, item);
    bin_heap2_remove_all(bh);
    bin_heap2_pop(bh, &item);
    ASSERT_EQ(0, item);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    bin_heap2_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_replace_test)
{
    const u32 WIDTH = 7;
    char      set[] = "XBQCTDM";
    char *    expected;

    struct bin_heap2 *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH + 1];
    merr_t                 err;
    int                    i, j;
    void *                 item = NULL;
    u32                    v;

    bin_heap2_create(WIDTH, u32_cmp, &bh);

    for (j = 0; j < WIDTH; ++j) {
        memset(handles, 0, sizeof(handles));
        for (i = 0; i < WIDTH; ++i) {
            err = sample_es_create(&es[i], set[i], SES_ONE);
            ASSERT_EQ(0, err);
            handles[i] = sample_es_get_es_handle(es[i]);
        }
        bin_heap2_prepare(bh, WIDTH, handles);

        sample_es_set_elt(es[j], 'A');
        bin_heap2_replace_src(bh, handles[j]);
        printf("replaced %c with %c\n", set[j], 'A');
        bin_heap2_pop(bh, &item);
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
        bin_heap2_prepare(bh, WIDTH, handles);

        sample_es_set_elt(es[j], 'E');
        bin_heap2_replace_src(bh, handles[j]);
        printf("replaced %c with %c\n", set[j], 'E');
        bin_heap2_pop(bh, &item);
        bin_heap2_pop(bh, &item);
        bin_heap2_pop(bh, &item);
        if (set[j] > 'E')
            bin_heap2_pop(bh, &item);

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
    bin_heap2_prepare(bh, WIDTH, handles);

    /* replace second half */
    for (i = WIDTH / 2; i < WIDTH; i++) {
        sample_es_set_elt(es[i], 'F' + i);
        bin_heap2_replace_src(bh, handles[i]);
    }

    expected = "BIJKLQX";
    printf("replaced %s with %s\n", set, expected);
    for (i = 0; i < WIDTH; i++) {
        bin_heap2_pop(bh, &item);
        v = *(u32 *)item;
        ASSERT_EQ(expected[i], v);
    }

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    bin_heap2_destroy(bh);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_basic)
{
    const u32 WIDTH = 17;

    struct bin_heap2 *     bh;
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

    bin_heap2_create(WIDTH, u32_cmp, &bh);

    bin_heap2_prepare(bh, WIDTH, handles);

    bin_heap2_pop(bh, &item);
    last = *(u32 *)item;

    while (bin_heap2_pop(bh, &item)) {
        value = *(u32 *)item;
        ASSERT_LE(last, value);
        last = value;
    }

    bin_heap2_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], 1123, SES_RANDOM);
        ASSERT_EQ(0, err);
        sample_es_sort(es[i]);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    bin_heap2_create(WIDTH, u32_cmp, &bh);

    bin_heap2_prepare(bh, WIDTH, handles);

    bin_heap2_pop(bh, &item);
    last = *(u32 *)item;

    while (bin_heap2_pop(bh, &item)) {
        value = *(u32 *)item;
        ASSERT_LE(last, value);
        last = value;
    }

    bin_heap2_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

#define getval(x) (*(x)&0xffffff)
#define getsrc(x) (*(x) >> 24)

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_dups)
{
    const u32 WIDTH = 3;

    struct bin_heap2 *     bh;
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

    err = bin_heap2_create(WIDTH, ks_cmp, &bh);
    ASSERT_EQ(0, err);

    bin_heap2_prepare(bh, WIDTH, handles);

    bin_heap2_pop(bh, (void **)&item);
    src = getsrc(item);
    last = getval(item);
    ASSERT_EQ(0, src);

    /* suppress dups */
    while (bin_heap2_peek(bh, (void **)&dup)) {
        if (getval(dup) != last)
            break;
        ASSERT_LT(src, getsrc(dup));
        bin_heap2_pop(bh, (void **)&dup);
    }

    while (bin_heap2_pop(bh, (void **)&item)) {
        ASSERT_LE(last, getval(item));
        ASSERT_EQ(0, getsrc(item));
        last = getval(item);

        /* suppress dups */
        while (bin_heap2_peek(bh, (void **)&dup)) {
            if (getval(dup) != last)
                break;
            ASSERT_LT(src, getsrc(dup));
            bin_heap2_pop(bh, (void **)&dup);
        }
    }

    bin_heap2_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_usage_error)
{
    const u32 WIDTH = 17;

    struct bin_heap2 *     bh;
    struct sample_es *     es[WIDTH];
    struct element_source *handles[WIDTH];
    merr_t                 err;
    int                    i;

    for (i = 0; i < WIDTH; ++i) {
        err = sample_es_create(&es[i], 1123, SES_LINEAR);
        ASSERT_EQ(0, err);
        handles[i] = sample_es_get_es_handle(es[i]);
    }

    err = bin_heap2_create(WIDTH - 1, u32_cmp, &bh);
    ASSERT_EQ(0, err);

    err = bin_heap2_prepare(bh, WIDTH, handles);
    ASSERT_EQ(merr_errno(err), EOVERFLOW);

    bin_heap2_destroy(bh);

    err = bin_heap2_create(WIDTH, u32_cmp, &bh);
    ASSERT_EQ(0, err);
    err = bin_heap2_prepare(bh, WIDTH, handles);
    ASSERT_EQ(0, err);

    bin_heap2_destroy(bh);

    for (i = 0; i < WIDTH; ++i)
        sample_es_destroy(es[i]);
}

MTF_DEFINE_UTEST(bin_heap_test, bin_heap2_age_cmp_test)
{
    struct element_source e1, e2;
    int                   rc;

    e1.es_sort = 10;
    e2.es_sort = 12;

    rc = bin_heap2_age_cmp(&e1, &e2);
    ASSERT_EQ(-2, rc);
}

MTF_END_UTEST_COLLECTION(bin_heap_test)
