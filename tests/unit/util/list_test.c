/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/list.h>

int
list_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
list_test_post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(list, list_test_pre, list_test_post);

MTF_DEFINE_UTEST(list, list_splice_test)
{
    struct list_head  list1;
    struct list_head  list2;
    struct list_head  elem1;
    struct list_head  elem2;
    struct list_head *pos;

    int cnt;

    cnt = 0;

    INIT_LIST_HEAD(&list1);
    INIT_LIST_HEAD(&list2);
    INIT_LIST_HEAD(&elem1);
    INIT_LIST_HEAD(&elem2);

    /* Splice does nothing if the new list to add is empty. */
    list_splice(&list1, &list2);

    list_add(&list1, &elem1);
    list_add(&list2, &elem2);
    /* Join list1 into list2. */
    list_splice(&list1, &list2);

    /* There should be two elements in the list now. */
    list_for_each (pos, &list2)
        ++cnt;

    ASSERT_EQ(2, cnt);
}

MTF_END_UTEST_COLLECTION(list)
