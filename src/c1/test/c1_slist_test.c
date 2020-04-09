/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_test_support/mock_api.h>
#include <hse_test_support/random_buffer.h>
#include <hse_util/slist.h>

static int
test_pre(struct mtf_test_info *ti)
{
    return 0;
}

static int
test_post(struct mtf_test_info *ti)
{
    return 0;
}

struct slist {
    struct s_list_head s_list;
    int                s_val;
};

MTF_BEGIN_UTEST_COLLECTION(c1_s_list_test)

MTF_DEFINE_UTEST_PREPOST(c1_s_list_test, basic, test_pre, test_post)
{
    struct s_list_head *tail;
    struct s_list_head  head;
    struct slist        a, b, c;
    struct s_list_head *p;

    int count;

    INIT_S_LIST_HEAD(&head);

    INIT_S_LISTH_NULL(&a.s_list);
    INIT_S_LIST_HEAD(&a.s_list);
    INIT_S_LIST_HEAD(&b.s_list);
    INIT_S_LIST_HEAD(&c.s_list);

    tail = &head;

    s_list_add_tail(&a.s_list, &tail);
    assert(tail == &a.s_list && tail->next == &head);
    s_list_add_tail(&b.s_list, &tail);
    assert(tail == &b.s_list && tail->next == &head);
    s_list_add_tail(&c.s_list, &tail);
    assert(tail == &c.s_list && tail->next == &head);

    count = 0;
    p = &head;
    while (p->next != &head) {
        ++count;
        p = p->next;
    }
    ASSERT_EQ(3, count);

    s_list_del_init(&c.s_list, &b.s_list, &tail);
    assert(tail == &b.s_list && tail->next == &head);
    s_list_del_init(&b.s_list, &a.s_list, &tail);
    assert(tail == &a.s_list && tail->next == &head);
    s_list_del_init(&a.s_list, &head, &tail);
    assert(tail == &head && head.next == &head);
}

MTF_END_UTEST_COLLECTION(c1_s_list_test);
