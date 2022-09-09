/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_TABLE_H
#define HSE_PLATFORM_TABLE_H

#include <hse_util/platform.h>

/**
 * table functions - implement a table abstraction around memory
 *
 * This structure wraps the common elements of dynamic arrays:
 * capacity, used, element size, and the dynamic array growth.
 *
 * All methods return a null pointer on failure.
 * The table methods return a table pointer.
 * The element methods return a void pointer to the array element.
 */

/**
 * struct table -
 * @cur:        max idx of current table usage
 * @capacity:   current maximum number of elements
 * @elemsz:     element size
 * @data:       ptr to table elements
 * @zerofill:   zero fill new allocations
 * @priv:       private ptr for use by owner
 */
struct table {
    uint   cur;
    uint   capacity;
    size_t elemsz;
    char * data;
    bool   zerofill;
    void * priv;
};

/**
 * table_sort() - sort elements in a table
 * @tab: table
 * @cmp: comparison function for elements
 */
static inline void
table_sort(struct table *tab, int (*cmp)(const void *, const void *))
{
    if (tab)
        qsort(tab->data, tab->cur, tab->elemsz, cmp);
}

/**
 * table_len() - return number of elements in table
 * @tab: table
 */
static inline uint
table_len(struct table *tab)
{
    return tab ? tab->cur : 0;
}

/**
 * table_at - return a pointer to the element at slot n
 * @tab: table
 * @n:   index into table
 */
static HSE_ALWAYS_INLINE void *
table_at(struct table *tab, uint n)
{
    if (!tab || !tab->data || n > tab->capacity)
        return NULL;

    return tab->data + (n * tab->elemsz);
}

/**
 * table_create() - create a table
 * @capacity:   initial number of elements
 * @elemsz:     element size
 * @zerofill:   zero each element if true
 */
struct table *
table_create(uint capacity, size_t elemsz, bool zerofill);

/**
 * table_destroy() - destroy a table
 * @tab: table
 *
 * %table_destroy releases memory allocated by the table methods.
 */
void
table_destroy(struct table *tab);

/**
 * table_reset - empty the table, prepare for reuse, preserves capacity
 * @tab: table
 *
 * table_reset simply clears all the memory in the table,
 * and resets the current element count to zero.
 */
struct table *
table_reset(struct table *tab);

/**
 * table_prune - remove the last item from the table
 * @tab: table
 *
 * table_prune simply zeros the last item and decrements the count.
 */
void
table_prune(struct table *tab);

/**
 * table_append - add an element to table, return ptr to element space
 * @tab: table
 *
 * table_append extends the table to allow for another element.
 * It returns a pointer to this space, and increments the count of elements.
 */
void *
table_append(struct table *tab);

/**
 * table_append_object - add this object to table, return ptr to element space
 * @tab: table
 *
 * table_append_object extends the table to allow for another element,
 * and copies this @tab->esz bytes from object ptr into this space.
 * It returns a pointer to this space, and increments the count of elements.
 */
void *
table_append_object(struct table *tab, void *p);

/**
 * table_insert - add an element at index n, return ptr to element space
 * @tab: table
 * @idx: index of new element
 *
 * table_insert returns a ptr to the element at @tab[@idx],
 * extending the table if necessary, and tracking the maximum @idx.
 */
void *
table_insert(struct table *tab, uint idx);

/**
 * table_apply - apply function to each element of table, in order
 * @tab:  table
 * @func: function to call for each element
 */
void
table_apply(struct table *tab, void (*func)(void *));

/**
 * table_apply_arg - apply function to each element of table, in order, with arg
 * @tab:  table
 * @func: function to call for each element
 * @arg:  arbitrary argument to add to each func call
 */
void
table_apply_arg(struct table *tab, void (*func)(void *, void *), void *arg);

/**
 * table_apply_rev - apply function to each element of table, in reverse order
 * @tab:  table
 * @func: function to call for each element
 */
void
table_apply_rev(struct table *tab, void (*func)(void *));

#endif /* HSE_PLATFORM_TABLE_H */
