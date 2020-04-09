/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_CDS_LIST_H
#define HSE_PLATFORM_CDS_LIST_H

#include <urcu/list.h>

static inline struct cds_list_head *
cds_list_first(struct cds_list_head *head)
{
    return cds_list_empty(head) ? (struct cds_list_head *)0 : head->next;
}

static inline struct cds_list_head *
cds_list_last(struct cds_list_head *head)
{
    return cds_list_empty(head) ? (struct cds_list_head *)0 : head->prev;
}

static inline struct cds_list_head *
cds_list_next(struct cds_list_head *item, struct cds_list_head *head)
{
    return item->next == head ? (struct cds_list_head *)0 : item->next;
}

static inline struct cds_list_head *
cds_list_prev(struct cds_list_head *item, struct cds_list_head *head)
{
    return item->prev == head ? (struct cds_list_head *)0 : item->prev;
}

#define cds_list_next_entry(item, head, member)                                    \
    ({                                                                             \
        struct cds_list_head *pos = cds_list_next(&(item)->member, (head));        \
        pos ? cds_list_entry(pos, typeof(*(item)), member) : (typeof(*(item)) *)0; \
    })

#define cds_list_prev_entry(item, head, member)                                    \
    ({                                                                             \
        struct cds_list_head *pos = cds_list_prev(&(item)->member, (head));        \
        pos ? cds_list_entry(pos, typeof(*(item)), member) : (typeof(*(item)) *)0; \
    })

#define cds_list_last_entry(type, head, member) \
    (cds_list_empty(head) ? (type *)0 : cds_list_entry((head)->prev, type, member))

#endif
