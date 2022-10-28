/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_LIST_H
#define HSE_PLATFORM_LIST_H

#include <hse/util/base.h>

struct list_head {
    struct list_head *prev, *next;
};

#define list_entry(addr, type, field) \
    ((type *)((char *)(addr) - (uintptr_t)(&((type *)0)->field)))

#define list_for_each(ptr, head) \
    for (ptr = (head)->next; ptr != (head); ptr = (ptr)->next)

/* The original for-each macros exhibit undefined behavior per the C spec
 * (6.2.3.2 (7)) when they generate an invalid item pointer with incorrect
 * alignment (as called out by ubsan).  We've fixed the macros to avoid
 * this problem, but note that the fix alters the semantics: At the end
 * of the iteration the item pointer is now NULL rather than pointing to
 * the head of the list.
 */
#define list_for_each_entry(item, head, field)                          \
    for (item = list_first_entry_or_null((head), typeof(*(item)), field); \
         (item);                                                        \
         item = list_next_entry_or_null((item), field, (head)))

#define list_for_each_entry_reverse(item, head, field)                  \
    for (item = list_last_entry_or_null((head), typeof(*(item)), field); \
         (item);                                                        \
         item = list_prev_entry_or_null((item), field, (head)))

#define list_for_each_entry_safe(item, nitem, head, field)              \
    for (item = list_first_entry_or_null((head), typeof(*(item)), field), \
             nitem = (item) ? list_next_entry_or_null((item), field, (head)) : NULL; \
         (item);                                                        \
         item = (nitem), nitem = (item) ? list_next_entry_or_null((item), field, (head)) : NULL)

#define list_for_each_entry_reverse_safe(item, nitem, head, field)              \
    for (item = list_last_entry_or_null((head), typeof(*(item)), field), \
             nitem = (item) ? list_prev_entry_or_null((item), field, (head)) : NULL; \
         (item);                                                        \
         item = (nitem), nitem = (item) ? list_prev_entry_or_null((item), field, (head)) : NULL)

static inline void
INIT_LIST_HEAD(struct list_head *head)
{
    head->prev = head->next = head;
}

static inline void
hse_list_add_helper(struct list_head *item, struct list_head *prev, struct list_head *next)
{
    prev->next = item;
    item->prev = prev;
    item->next = next;
    next->prev = item;
}

/**
 * Add @item after head.
 */
static inline void
list_add(struct list_head *item, struct list_head *head)
{
    hse_list_add_helper(item, head, head->next);
}

/**
 * Add @item before head.
 */
static inline void
list_add_tail(struct list_head *item, struct list_head *head)
{
    hse_list_add_helper(item, head->prev, head);
}

static inline void
list_del(struct list_head *item)
{
    item->prev->next = item->next;
    item->next->prev = item->prev;
}

static inline void
list_del_init(struct list_head *item)
{
    list_del(item);
    INIT_LIST_HEAD(item);
}

static inline int
list_empty(const struct list_head *head)
{
    return head->next == head;
}

static inline void
hse_list_splice_helper(const struct list_head *list, struct list_head *prev, struct list_head *next)
{
    list->next->prev = prev;
    prev->next = list->next;
    list->prev->next = next;
    next->prev = list->prev;
}

/**
 * list_splice - join two lists
 * @list: the new list to add.
 * @head: add the list after @head.
 */
static inline void
list_splice(const struct list_head *list, struct list_head *head)
{
    if (!list_empty(list))
        hse_list_splice_helper(list, head, head->next);
}

/**
 * list_splice_tail - join two lists
 * @list: the list to add.
 * @head: add the list before @head.
 */
static inline void
list_splice_tail(const struct list_head *list, struct list_head *head)
{
    if (!list_empty(list))
        hse_list_splice_helper(list, head->prev, head);
}

static inline int
list_is_first(const struct list_head *item, const struct list_head *head)
{
    return !list_empty(head) && item->prev == head;
}

static inline int
list_is_last(const struct list_head *item, const struct list_head *head)
{
    return !list_empty(head) && item->next == head;
}

#define list_first_entry(head, type, field) list_entry((head)->next, type, field)

#define list_last_entry(head, type, field) list_entry((head)->prev, type, field)

#define list_first_entry_or_null(head, type, field) \
    (!list_empty(head) ? list_first_entry(head, type, field) : NULL)

#define list_last_entry_or_null(head, type, field) \
    (!list_empty(head) ? list_last_entry(head, type, field) : NULL)

#define list_prev_entry(item, field) list_entry((item)->field.prev, typeof(*(item)), field)

#define list_prev_entry_or_null(item, field, head) \
    ((!list_is_first(&(item)->field, head)) ? list_prev_entry(item, field) : NULL)

#define list_next_entry(item, field) list_entry((item)->field.next, typeof(*(item)), field)

#define list_next_entry_or_null(item, field, head) \
    ((!list_is_last(&(item)->field, head)) ? list_next_entry(item, field) : NULL)

/**
 * list_trim() - trim the tail off a list
 * @list:   new list into which the tail will be put
 * @head:   head of the list to trim
 * @entry:  an entry within head which identifies the tail
 *
 * list_trim() is similar to list_cut_position(), except that it lops
 * off the tail of the list and leaves the head in place.  All entries
 * from %head starting with and including %entry are put into %list
 * with ordering preserved.  Note that %list is always clobbered.
 */
static inline void
list_trim(struct list_head *list, struct list_head *head, struct list_head *entry)
{
    INIT_LIST_HEAD(list);

    if (list_empty(head))
        return;

    if (entry == head) {
        list_splice(head, list);
    } else {
        struct list_head *last = head->prev;

        list->next = entry;
        list->prev = last;

        entry->prev->next = head;
        head->prev = entry->prev;

        entry->prev = list;
        last->next = list;
    }
}
#endif
