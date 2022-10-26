/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mock/api.h>

#include <hse/util/table.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(table);

MTF_DEFINE_UTEST(table, table_create_test)
{
    struct table *tab;

    mapi_inject_unset(mapi_idx_malloc);
    mapi_inject_once_ptr(mapi_idx_malloc, 1, 0);
    tab = table_create(10, sizeof(void *), false);
    ASSERT_EQ(NULL, tab);

    mapi_inject_unset(mapi_idx_malloc);
    mapi_inject_once_ptr(mapi_idx_malloc, 1, 0);
    tab = table_create(10, sizeof(void *), true);
    ASSERT_EQ(NULL, tab);

    tab = table_create(10, sizeof(void *), false);
    ASSERT_NE(NULL, tab);
    ASSERT_EQ(0, table_len(tab));
    table_destroy(tab);

    tab = table_create(0, sizeof(struct table *), false);
    ASSERT_NE(NULL, tab);
    ASSERT_EQ(0, table_len(tab));
    ASSERT_NE(NULL, table_append_object(tab, tab));
    table_destroy(tab);
}

const int limit = 1000;
char      buf[100];
struct object {
    int   i;
    char *p;
};

MTF_DEFINE_UTEST(table, grow1)
{
    struct object *o;
    struct table * tab;
    int            i;

    mapi_inject_unset(mapi_idx_malloc);

    tab = table_create(0, sizeof(*o), true);
    ASSERT_NE(NULL, tab);

    for (i = 0; i < limit; ++i) {
        sprintf(buf, "string %d", i);
        o = table_insert(tab, i);
        ASSERT_TRUE(o != 0);
        o->i = i;
        o->p = strdup(buf);
    }
    ASSERT_LE(limit, table_len(tab));

    for (i = 0; i < limit; ++i) {
        sprintf(buf, "string %d", i);
        o = table_at(tab, i);
        ASSERT_TRUE(o != 0);
        ASSERT_EQ(0, strcmp(o->p, buf));
        free(o->p);
    }

    table_destroy(tab);
}

MTF_DEFINE_UTEST(table, grow13)
{
    struct object *o, obj;
    struct table * tab;
    int            i;

    tab = table_create(0, sizeof(*o), true);
    ASSERT_NE(NULL, tab);

    for (i = 0; i < limit; ++i) {
        sprintf(buf, "string %d", i);
        obj.i = i;
        obj.p = strdup(buf);
        ASSERT_NE(NULL, obj.p);
        ASSERT_TRUE(table_append_object(tab, &obj) != 0);
    }
    ASSERT_LE(limit, table_len(tab));

    for (i = 0; i < limit; ++i) {
        sprintf(buf, "string %d", i);
        o = table_at(tab, i);
        ASSERT_EQ(0, strcmp(o->p, buf));
        free(o->p);
    }

    table_destroy(tab);
}

/*
 * NB: test the apply funcs with the identity sum(1..N) = (N+1)*(N/2)
 *     This guarantees every element is touched exactly once,
 *     including the edges (catches off-by-one problems).
 */

static int tot;

static void
applyfunc(void *p)
{
    tot += *(int *)p;
}

static void
applyargfunc(void *p, void *a)
{
    tot += *(int *)p;
    tot -= *(int *)a;
}

MTF_DEFINE_UTEST(table, apply)
{
    struct table *tab;
    int           i;

    tab = table_create(100, sizeof(i), true);
    ASSERT_NE(NULL, tab);

    tot = 0;
    for (i = 1; i <= 100; ++i)
        table_append_object(tab, &i);
    table_apply(tab, applyfunc);
    ASSERT_EQ(tot, (100 + 1) * 100 / 2);

    table_destroy(tab);
}

MTF_DEFINE_UTEST(table, apply_arg)
{
    struct table *tab;
    int           i;

    tab = table_create(100, sizeof(i), true);
    ASSERT_NE(NULL, tab);

    tot = 0;
    for (i = 1; i <= 100; ++i)
        table_append_object(tab, &i);
    i = 3;
    table_apply_arg(tab, applyargfunc, &i);
    ASSERT_EQ(tot, (100 + 1) * 100 / 2 - 300);

    table_destroy(tab);
}

MTF_DEFINE_UTEST(table, apply_rev)
{
    struct table *tab;
    int           i;

    tab = table_create(100, sizeof(i), true);
    ASSERT_NE(NULL, tab);

    tot = 0;
    for (i = 1; i <= 100; ++i)
        table_append_object(tab, &i);
    table_apply_rev(tab, applyfunc);
    ASSERT_EQ(tot, (100 + 1) * 100 / 2);

    table_destroy(tab);
}

MTF_DEFINE_UTEST(table, random_access)
{
    struct table *tab;

    tab = table_create(100, sizeof(char *), true);
    ASSERT_NE(NULL, tab);

    *(char **)table_insert(tab, 42) = "foo";
    *(char **)table_insert(tab, 69) = "bar";

    ASSERT_EQ(70, table_len(tab));
    ASSERT_LE(100, tab->capacity);
    ASSERT_EQ(0, strcmp(*(char **)table_at(tab, 42), "foo"));
    ASSERT_EQ(0, strcmp(*(char **)table_at(tab, 69), "bar"));

    table_destroy(tab);
}

MTF_DEFINE_UTEST(table, reset)
{
    struct table *tab;
    int           i;

    tab = table_create(100, sizeof(i), true);
    ASSERT_NE(NULL, tab);

    for (i = 0; i < 100; ++i)
        *(int *)table_append(tab) = i;

    ASSERT_EQ(100, tab->cur);
    ASSERT_LE(100, tab->capacity);
    ASSERT_EQ(49, *(int *)table_at(tab, 49));
    ASSERT_EQ(99, *(int *)table_at(tab, 99));

    table_reset(tab);

    ASSERT_EQ(0, tab->cur);
    ASSERT_LE(100, tab->capacity);
    ASSERT_EQ(0, *(int *)table_at(tab, 0));
    ASSERT_EQ(0, *(int *)table_at(tab, 49));
    ASSERT_EQ(0, *(int *)table_at(tab, 99));

    table_destroy(tab);
}

MTF_END_UTEST_COLLECTION(table);
