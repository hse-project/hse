/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/alloc.h>
#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/event_counter.h>
#include <hse_util/table.h>

struct table *
table_create(uint capacity, size_t elemsz, bool zerofill)
{
    struct table *tab;
    void *        mem;
    size_t        sz;

    if (capacity == 0)
        capacity = 1;

    sz = ALIGN(capacity * elemsz, 128);
    capacity = sz / elemsz;

    if (zerofill)
        mem = calloc(capacity, elemsz);
    else
        mem = malloc(sz);

    if (ev(!mem))
        return NULL;

    tab = malloc(sizeof(*tab));
    if (ev(!tab)) {
        free(mem);
        return NULL;
    }

    tab->cur = 0;
    tab->capacity = capacity;
    tab->elemsz = elemsz;
    tab->data = mem;
    tab->zerofill = zerofill;
    tab->priv = NULL;

    return tab;
}

struct table *
table_calloc(uint capacity, size_t elemsz)
{
    return table_create(capacity, elemsz, true);
}

void
table_destroy(struct table *tab)
{
    if (!tab)
        return;

    free(tab->data);
    tab->data = (void *)-1;
    free(tab);
    ev(1);
}

struct table *
table_reset(struct table *tab)
{
    if (tab->zerofill)
        memset(tab->data, 0, tab->capacity * tab->elemsz);
    tab->cur = 0;

    return tab;
}

void
table_prune(struct table *tab)
{
    if (tab && tab->cur > 0) {
        tab->cur--;
        if (tab->zerofill)
            memset(table_at(tab, tab->cur), 0, tab->elemsz);
    }
}

static void *
table_grow(struct table *tab, uint n)
{
    size_t sz;
    void * p;

    if (ev(n > tab->capacity)) {
        if (n < tab->capacity * 2)
            n = tab->capacity * 2;

        sz = ALIGN(n * tab->elemsz, 128);
        n = sz / tab->elemsz;

        p = realloc(tab->data, sz);
        if (!p)
            return 0;

        tab->data = p;
        if (tab->zerofill)
            memset(table_at(tab, tab->capacity), 0, (n - tab->capacity) * tab->elemsz);
        tab->capacity = n;
    }

    return table_at(tab, tab->cur);
}

void *
table_append(struct table *tab)
{
    void *p = table_at(tab, tab->cur);

    if (tab->cur + 1 > tab->capacity)
        p = table_grow(tab, tab->cur + 1);

    if (p)
        ++tab->cur;

    return p;
}

void *
table_append_object(struct table *tab, void *p)
{
    void *space = table_append(tab);

    if (space)
        memcpy(space, p, tab->elemsz);
    return space;
}

void *
table_insert(struct table *tab, uint idx)
{
    if (idx >= tab->capacity)
        if (!table_grow(tab, idx + 1))
            return 0;
    if (idx >= tab->cur)
        tab->cur = idx + 1;
    return table_at(tab, idx);
}

void
table_apply(struct table *tab, void (*func)(void *))
{
    uint i;

    for (i = 0; i < tab->cur; ++i)
        func(table_at(tab, i));
}

void
table_apply_arg(struct table *tab, void (*func)(void *, void *), void *arg)
{
    uint i;

    for (i = 0; i < tab->cur; ++i)
        func(table_at(tab, i), arg);
}

void
table_apply_rev(struct table *tab, void (*func)(void *))
{
    uint i;

    for (i = tab->cur; i > 0; --i)
        func(table_at(tab, i - 1));
}
