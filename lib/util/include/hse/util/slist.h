/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_SLIST_H
#define HSE_PLATFORM_SLIST_H

#include <hse/util/base.h>

/*
 * Simple circular singly linked list implementation that
 * resembles a subset of Linux kernel definitions in
 * <linux/list.h>.
 */

struct s_list_head {
    struct s_list_head *next;
};

#define S_LIST_HEAD_INIT(var_name) \
    {                              \
        &(var_name)                \
    }

#define S_LIST_HEAD(var_name) struct s_list_head var_name = S_LIST_HEAD_INIT(var_name)

#define s_list_is_last(item, head) ((item)->next == (head))

#define s_list_empty(head) ((head)->next == (head))

#define s_list_null(head) ((head)->next == NULL)

#define s_list_entry(ptr, type, member) container_of(ptr, type, member)

#define s_list_first_entry(head, type, member) s_list_entry((head)->next, type, member)

#define s_list_first_entry_or_null(head, type, member) \
    (!s_list_empty(head) ? s_list_first_entry(head, type, member) : NULL)

#define s_list_next_entry(pos, member) s_list_entry((pos)->member.next, typeof(*(pos)), member)

#define s_list_next_entry_or_null(pos, member) \
    ((!s_list_is_last(&(pos)->member)) ? s_list_next_entry(pos, member) : NULL)

#define s_list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)

#define s_list_for_each_entry(pos, head, member)                                       \
    for (pos = s_list_first_entry(head, typeof(*pos), member); &pos->member != (head); \
         pos = s_list_next_entry(pos, member))

#define s_list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)

#define s_list_for_each_entry_safe(pos, n, head, member)                                           \
    for (pos = s_list_first_entry(head, typeof(*pos), member), n = s_list_next_entry(pos, member); \
         &pos->member != (head); pos = n, n = s_list_next_entry(pos, member))

static inline void
INIT_S_LIST_HEAD(struct s_list_head *head)
{
    head->next = head;
}

static inline void
INIT_S_LISTH_NULL(struct s_list_head *head)
{
    head->next = NULL;
}

static inline void
s_list_add_tail(struct s_list_head *item, struct s_list_head **newtail)
{
    item->next = (*newtail)->next;
    (*newtail)->next = item;
    *newtail = item;
}

static inline void
s_list_del(struct s_list_head *item, struct s_list_head *prev, struct s_list_head **newtail)
{
    if (newtail && *newtail == item)
        *newtail = prev;
    prev->next = item->next;
}

static inline void
s_list_del_init(struct s_list_head *item, struct s_list_head *prev, struct s_list_head **newtail)
{
    s_list_del(item, prev, newtail);
    INIT_S_LIST_HEAD(item);
}
#endif /* HSE_PLATFORM_SLIST_H */
