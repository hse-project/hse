/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_ut/common.h>

#if HSE_MOCKING
#include <hse_test_support/allocation.h>
#endif /* HSE_MOCKING */

#include <hse_util/xrand.h>

#include <hse_util/slab.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/logging.h>
#include <hse_util/printbuf.h>

#include <hse_util/data_tree.h>

#include "multithreaded_tester.h"

int
platform_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PRE(data_tree, platform_pre);

MTF_DEFINE_UTEST(data_tree, tree_create_and_destroy)
{
    struct dt_tree *tree;
    int             ret;

    tree = dt_create("data");
    ASSERT_NE(tree, NULL);

    /* Now iterate starting at the top and make sure you see one element */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/data", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 1);

    dt_destroy(tree);
}

#if HSE_MOCKING
MTF_DEFINE_UTEST_PREPOST(
    data_tree,
    tree_alloc_error,
    fail_nth_alloc_test_pre,
    fail_nth_alloc_test_post)
{
    struct dt_tree *tree;

    g_fail_nth_alloc_cnt = 0;
    g_fail_nth_alloc_limit = 0;

    tree = dt_create("data");
    ASSERT_EQ(tree, NULL);
}
#endif /* HSE_MOCKING */

struct test_element {
    int num;
};

static int test_element_remove_handler_hit;
static int test_element_emit_handler_hit;
static int test_element_set_handler_hit;
static int test_element_count_handler_hit;

void
clear_handler_counts(void)
{
    test_element_emit_handler_hit = 0;
    test_element_set_handler_hit = 0;
    test_element_count_handler_hit = 0;
    test_element_remove_handler_hit = 0;
}

size_t
test_element_remove_handler(struct dt_element *element)
{
    test_element_remove_handler_hit++;
    if (element->dte_data) {
        /* Free the underlying data object */
        free(element->dte_data);
    }
    free(element);
    return 0;
}

#define FIXED_EMIT_SIZE 50
size_t
test_element_emit_handler(struct dt_element *element, struct yaml_context *yc)
{
    test_element_emit_handler_hit++;

    if (FIXED_EMIT_SIZE > yc->yaml_buf_sz - yc->yaml_offset) {
        /* Would overflow */
        yc->yaml_offset = yc->yaml_buf_sz;
    } else {
        /* will fit */
        yc->yaml_offset += FIXED_EMIT_SIZE;
    }
    return 1;
}

static int test_element_alt_emit_handler_hit;
size_t
test_element_alt_emit_handler(struct dt_element *element, struct yaml_context *yc)
{
    test_element_alt_emit_handler_hit++;
    yaml_start_element(yc, "path", element->dte_path);
    yaml_end_element(yc);

    return 1;
}

size_t
test_element_set_handler(struct dt_element *element, struct dt_set_parameters *dsp)
{
    test_element_set_handler_hit++;
    return 1;
}

size_t
test_element_count_handler(struct dt_element *element)
{
    test_element_count_handler_hit++;
    return 1;
}

struct dt_element_ops test_element_ops = {
    .remove = test_element_remove_handler,
    .emit = test_element_emit_handler,
    .set = test_element_set_handler,
    .count = test_element_count_handler,
};

struct dt_element_ops test_element_alt_ops = {
    .remove = test_element_remove_handler,
    .emit = test_element_alt_emit_handler,
    .set = test_element_set_handler,
    .count = test_element_count_handler,
};

MTF_DEFINE_UTEST(data_tree, tree_create_and_add)
{
    int                  rc;
    struct dt_tree *     tree;
    struct dt_element *  element;
    struct test_element *te;

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    /* Now add a test_element */
    element = calloc(1, sizeof(*element));
    ASSERT_NE(element, NULL);

    te = calloc(1, sizeof(*te));
    ASSERT_NE(te, NULL);

    snprintf(element->dte_path, sizeof(element->dte_path), "/test/test_element/one");
    element->dte_data = te;
    element->dte_ops = &test_element_ops;
    element->dte_type = DT_TYPE_TEST_ELEMENT;

    rc = dt_add(tree, NULL);
    ASSERT_EQ(rc, -EINVAL);

    rc = dt_add(tree, element);
    ASSERT_EQ(rc, 0);

    rc = dt_add(tree, element);
    ASSERT_EQ(rc, -EEXIST);

    dt_destroy(tree);
}

MTF_DEFINE_UTEST(data_tree, get_tree)
{
    struct dt_tree *     tree, *found_tree;
    struct dt_element *  element;
    struct test_element *te;

    char buf[1024];

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    /* Now add a test_element */
    element = calloc(1, sizeof(*element));
    ASSERT_NE(element, NULL);

    te = calloc(1, sizeof(*te));
    ASSERT_NE(te, NULL);

    snprintf(element->dte_path, sizeof(element->dte_path), "/test/test_element/one");
    element->dte_data = te;
    element->dte_ops = &test_element_ops;
    element->dte_type = DT_TYPE_TEST_ELEMENT;

    dt_add(tree, element);

    found_tree = dt_get_tree("/test");
    ASSERT_EQ(found_tree, tree);

    found_tree = dt_get_tree("/test/test_element");
    ASSERT_EQ(found_tree, tree);

    found_tree = dt_get_tree("/test/test_element/one");
    ASSERT_EQ(found_tree, tree);

    dt_tree_emit_pathbuf("/test", buf, sizeof(buf));

    dt_destroy(tree);
}

MTF_DEFINE_UTEST(data_tree, tree_create_illegal_name)
{
    struct dt_tree *tree;
    char *          overlength_name = "abcdefghijklmnopqrstuvwxyz012345";

    tree = dt_create(overlength_name);
    ASSERT_EQ(tree, NULL);
}

static struct dt_element *
add_test_element(struct dt_tree *tree, char *path, int num)
{
    struct dt_element *  element;
    struct test_element *te;

    element = calloc(1, sizeof(*element));

    te = calloc(1, sizeof(*te));

    snprintf(element->dte_path, sizeof(element->dte_path), "%s", path);
    element->dte_data = te;
    element->dte_ops = &test_element_ops;
    element->dte_type = DT_TYPE_TEST_ELEMENT;
    element->dte_severity = HSE_INFO_VAL;
    te->num = num;

    dt_add(tree, element);

    return element;
}

#define TEST_ELEMENT_OPS_BUF_SIZE 4096
MTF_DEFINE_UTEST(data_tree, test_element_ops_function)
{
    struct dt_tree *    tree;
    struct dt_element * element;
    struct yaml_context yc = {
        .yaml_offset = 0, .yaml_indent = 0,
    };
    struct dt_set_parameters dsp;
    int                      ret;
    char *                   buf;

    clear_handler_counts();
    dsp.value = "foo";
    dsp.value_len = strlen(dsp.value);

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    /* Now add a test_element */
    element = add_test_element(tree, "/test/test_element/one", 1);

    buf = calloc(TEST_ELEMENT_OPS_BUF_SIZE, 1);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = TEST_ELEMENT_OPS_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Test Emit Handler */
    ret = element->dte_ops->emit(element, &yc);

    ASSERT_EQ(test_element_emit_handler_hit, 1);
    ASSERT_EQ(yc.yaml_offset, FIXED_EMIT_SIZE);

    /* Test Set Handler */
    ret = element->dte_ops->set(element, &dsp);
    ASSERT_EQ(test_element_set_handler_hit, 1);

    /* Test Count Handler */
    ret = element->dte_ops->count(element);
    ASSERT_EQ(ret, 1);

    /* Test Remove Handler */
    ret = dt_remove(tree, element);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(test_element_remove_handler_hit, 1);

    dt_destroy(tree);

    free(buf);
}

#define TEST_ELEMENT_OPS_SHORT_BUF_SIZE 128
MTF_DEFINE_UTEST(data_tree, test_emit_overflow_protection)
{
    struct dt_tree *    tree;
    struct dt_element * element[3];
    struct yaml_context yc = {
        .yaml_offset = 0, .yaml_indent = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };
    char *                      buf;
    int                         i;

    clear_handler_counts();

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    /* Now add several test_elements */
    for (i = 0; i < 3; i++) {
        char name[32];

        snprintf(name, sizeof(name), "/test/test%d", i);
        element[i] = add_test_element(tree, name, 1);
        ASSERT_NE(element[i], NULL);
    }

    buf = calloc(TEST_ELEMENT_OPS_SHORT_BUF_SIZE, 1);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = TEST_ELEMENT_OPS_SHORT_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Try to overflow */
    dt_iterate_cmd(tree, DT_OP_EMIT, "/test", &dip, NULL, NULL, NULL);

    ASSERT_EQ(yc.yaml_offset, TEST_ELEMENT_OPS_SHORT_BUF_SIZE);

    dt_destroy(tree);

    free(buf);
}

MTF_DEFINE_UTEST(data_tree, test_remove_protection)
{
    struct dt_tree *   tree;
    struct dt_element *element1, *element2;
    int                ret;

    clear_handler_counts();

    tree = dt_create("test2");
    ASSERT_NE(tree, NULL);

    element1 = add_test_element(tree, "/test/one", 1);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element(tree, "/test/two", 2);
    ASSERT_NE(element2, NULL);

    /* Make element1 non-removable */
    element1->dte_flags |= DT_FLAGS_NON_REMOVEABLE;

    /* Try to remove element1, should fail */
    ret = dt_remove(tree, element1);
    ASSERT_EQ(ret, -EACCES);

    dt_destroy(tree);
}

MTF_DEFINE_UTEST(data_tree, test_find)
{
    struct dt_tree *   tree;
    struct dt_element *element1, *element2, *element4;
    struct dt_element *found;

    clear_handler_counts();

    tree = dt_create("test1");
    ASSERT_NE(tree, NULL);

    element1 = add_test_element(tree, "/test1/one", 1);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element(tree, "/test1/one/two", 2);
    ASSERT_NE(element2, NULL);

    element4 = add_test_element(tree, "/test1/one/two/three/four", 4);
    ASSERT_NE(element4, NULL);

    /* Find each element by exact search */
    found = dt_find(tree, "/test1/one", 1);
    ASSERT_EQ(found, element1);

    found = dt_find(tree, "/test1/one/two", 1);
    ASSERT_EQ(found, element2);

    found = dt_find(tree, "/test1/one/two/three/four", 1);
    ASSERT_EQ(found, element4);

    /* Try to find 'three' and prove that exact search doesn't find it */
    found = dt_find(tree, "/test1/one/two/three", 1);
    ASSERT_EQ(found, NULL);

    /* Now find element4 with a fuzzy search starting at '.../three' */
    found = dt_find(tree, "/test1/one/two/three", 0);
    ASSERT_EQ(found, element4);

    dt_destroy(tree);
}

MTF_DEFINE_UTEST(data_tree, test_iterate_with_command)
{
    struct dt_tree *   tree;
    struct dt_element *element1, *element2, *element4;
    int                ret;

    clear_handler_counts();

    tree = dt_create("test1");
    ASSERT_NE(tree, NULL);

    element1 = add_test_element(tree, "/test1/one", 1);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element(tree, "/test1/one/two", 2);
    ASSERT_NE(element2, NULL);

    element4 = add_test_element(tree, "/test1/one/two/three/four", 4);
    ASSERT_NE(element4, NULL);

    /* Now iterate starting at the top and make sure you see
     * four elements (root + the 3 new elements.
     */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test1", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 4);

    /* Now iterate starting in the middle, should see two */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test1/one/two", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 2);

    dt_destroy(tree);
}

static int
select_for_debug(struct dt_element *element)
{
    if (element->dte_severity <= HSE_DEBUG_VAL) {
        /* We want this one */
        return 1;
    }
    return 0;
}

static int
select_for_info(struct dt_element *element)
{
    if (element->dte_severity <= HSE_INFO_VAL) {
        /* We want this one */
        return 1;
    }
    return 0;
}

static int
select_for_err(struct dt_element *element)
{
    if (element->dte_severity <= HSE_ERR_VAL) {
        /* We want this one */
        return 1;
    }
    return 0;
}

MTF_DEFINE_UTEST(data_tree, test_selection_callback)
{
    struct dt_tree *   tree;
    struct dt_element *element1, *element2, *element3, *element4;
    int                ret;

    clear_handler_counts();

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    /* Create an element with a severity of HSE_ERR_VAL */
    element1 = add_test_element(tree, "/test/one", 1);
    ASSERT_NE(element1, NULL);

    element1->dte_severity = HSE_ERR_VAL;

    /* Create an element with a severity of HSE_INFO_VAL */
    element2 = add_test_element(tree, "/test/two", 1);
    ASSERT_NE(element2, NULL);

    element2->dte_severity = HSE_INFO_VAL;

    /* Create an element with a severity of HSE_DEBUG_VAL */
    element3 = add_test_element(tree, "/test/three", 1);
    ASSERT_NE(element3, NULL);

    element3->dte_severity = HSE_DEBUG_VAL;

    /* Create an element with no explicit severity.
     * Should default to HSE_INFO_VAL.
     */
    element4 = add_test_element(tree, "/test/four", 1);
    ASSERT_NE(element4, NULL);

    /* Now, select for severity <= HSE_DEBUG_VAL.
     * Should get 5 back (root + 4 new elements).
     */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test", NULL, select_for_debug, NULL, NULL);
    ASSERT_EQ(ret, 5);

    /* Now, select for severity <= HSE_INFO_VAL.
     * Should get 4 back.
     */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test", NULL, select_for_info, NULL, NULL);
    ASSERT_EQ(ret, 4);

    /* Now, select for severity <= HSE_ERR_VAL.
     * Should get 2 back.
     */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test", NULL, select_for_err, NULL, NULL);
    ASSERT_EQ(ret, 2);

    dt_destroy(tree);
}

MTF_DEFINE_UTEST(data_tree, test_iterate)
{
    struct dt_tree *   tree;
    struct dt_element *element[4];
    struct dt_element *found;
    int                found_count;

    clear_handler_counts();

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    element[0] = add_test_element(tree, "/test/a", 1);
    ASSERT_NE(element[0], NULL);

    element[1] = add_test_element(tree, "/test/a/b", 1);
    ASSERT_NE(element[1], NULL);

    element[2] = add_test_element(tree, "/test/a/b/d", 1);
    ASSERT_NE(element[2], NULL);

    element[3] = add_test_element(tree, "/test/a/c", 1);
    ASSERT_NE(element[3], NULL);

    /* Should find all 4 elements plus the root if I start at /test */
    found_count = 0;
    found = NULL;
    do {
        found = dt_iterate_next(tree, "/test/a", found);
        if (found) {
            ASSERT_EQ(found, element[found_count]);
            found_count++;
        }
    } while (found != NULL);

    ASSERT_EQ(found_count, 4);

    /* Should find all 2 elements if I start at /test/one/two */
    found_count = 0;
    found = NULL;
    do {
        found = dt_iterate_next(tree, "/test/a/b", found);
        if (found) {
            ASSERT_EQ(found, element[found_count + 1]);
            found_count++;
        }
    } while (found != NULL);

    ASSERT_EQ(found_count, 2);

    dt_destroy(tree);
}

/* Start Test: multi-writer, no reader */
struct mtest *mtest;

#define WORK_TYPE_ADD 0x1
#define WORK_TYPE_DEL 0x2
#define WORK_TYPE_FIND 0x4
#define WORK_TYPE_ITER 0x8

struct test_worker {
    struct dt_tree *tree;
    uint32_t        work_type;
    int             count_per_loop;
    int             loop_count;
};

struct test {
    int                   worker_count;
    struct mtf_test_info *lcl_ti;
    struct test_worker *  worker;
};

MTF_DEFINE_UTEST(data_tree, remove_recursive)
{
    struct dt_element *element;
    struct dt_tree *   tree;
    int                ret;

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    element = add_test_element(tree, "/test/A/one", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element(tree, "/test/A/two", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element(tree, "/test/A/B/three", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element(tree, "/test/A/B/four", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element(tree, "/test/C/five", 1);
    ASSERT_NE(element, NULL);

    /* Now iterate starting at the top and make sure you see six elements */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 6);

    /* Now recursively remove the /test/A sub-tree */
    ret = dt_remove_recursive(tree, "/test/A");
    ASSERT_EQ(ret, 0);

    /* Now there should be two items left */
    ret = dt_iterate_cmd(tree, DT_OP_COUNT, "/test", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 2);

    dt_destroy(tree);
}

static int fail_err;
static int fail_line;

static void
worker(void *context, int id)
{
    struct test *       test = context;
    struct test_worker *work = &(test->worker[id]);
    struct dt_element * dte, *prev, *found;
    int                 i, loop;
    struct yaml_context yc = {
        .yaml_offset = 0, .yaml_indent = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };

    mtest_barrier(mtest);

    for (loop = 0; loop < work->loop_count; loop++) {
        if (work->work_type & WORK_TYPE_ADD) {
            for (i = 0; i < test->worker[id].count_per_loop; i++) {
                dte = calloc(1, sizeof(*dte));
                if (!dte) {
                    fail_line = __LINE__;
                    fail_err = ENOMEM;
                    return;
                }

                sprintf(dte->dte_path, "/test/worker%d/node%d", id, i);
                dte->dte_ops = &test_element_alt_ops;
                dte->dte_type = DT_TYPE_DONT_CARE;
                dt_add(test->worker[id].tree, dte);
            }
        }
        if (work->work_type & WORK_TYPE_FIND) {
            for (i = 0; i < work->count_per_loop; i++) {
                char path[DT_PATH_LEN];

                sprintf(path, "/test/worker%d/node%d", id, i);
                dte = dt_find(work->tree, path, 1);
                if (!dte) {
                    fail_line = __LINE__;
                    fail_err = ENOENT;
                    return;
                }
            }
        }
        if (work->work_type & WORK_TYPE_ITER) {
            char   path[DT_PATH_LEN];
            char * buf;
            size_t buf_sz;
            size_t iter_count = 0;

            buf_sz = (work->count_per_loop + 1) * sizeof(path);
            buf = calloc(1, buf_sz);
            yc.yaml_buf = buf;
            yc.yaml_buf_sz = buf_sz;
            yc.yaml_emit = NULL;

            sprintf(path, "/test/worker%d", id);
            iter_count = dt_iterate_cmd(work->tree, DT_OP_EMIT, path, &dip, NULL, NULL, NULL);
            /* Plus 1 for root (i.e. "/test" */
            if (iter_count != (work->count_per_loop + 1)) {
                fail_line = __LINE__;
                fail_err = EINVAL;
                return;
            }
            free(buf);
        }
        if (work->work_type & WORK_TYPE_DEL) {
            char path[DT_PATH_LEN];

            sprintf(path, "/test/worker%d", id);
            found = dt_iterate_next(work->tree, path, NULL);
            do {
                prev = found;
                if (prev == NULL) {
                    /* There is an error here, this should not be needed, we should
                     * break at the while(). But we are not.
                     */
                    break;
                }
                found = dt_iterate_next(work->tree, path, found);
                dt_remove(work->tree, prev);
            } while (found);
        }
    }
}

static void
report(void *context, double elapsed_time)
{
    struct test *test = (struct test *)context;
    int          count = 0;
    int          i;

    /* Count up how many to expect */
    for (i = 0; i < test->worker_count; i++) {
        count += test->worker[i].count_per_loop * test->worker[i].loop_count;
    }
    printf("%s: expected count %d\n", __func__, count);
}

MTF_DEFINE_UTEST(data_tree, multithreaded_stress)
{
    struct dt_tree *tree;
    struct test     test;
    int             worker_count = 5;
    int             per_worker_count = 1000;
    int             i;

    clear_handler_counts();

    tree = dt_create("test");
    ASSERT_NE(tree, NULL);

    /* Test will have two WRITER_ADDER workers */
    test.worker = calloc(worker_count, sizeof(*test.worker));
    ASSERT_NE(test.worker, NULL);

    for (i = 0; i < worker_count; i++) {
        test.worker[i].tree = tree;
        test.worker[i].work_type |= WORK_TYPE_ADD;
        test.worker[i].work_type |= WORK_TYPE_DEL;
        test.worker[i].work_type |= WORK_TYPE_ITER;
        test.worker[i].work_type |= WORK_TYPE_FIND;
        test.worker[i].loop_count = ((i + 1) * worker_count);
        test.worker[i].count_per_loop = ((i + 1) * per_worker_count);
    }

    test.worker_count = worker_count;

    mtest = mtest_create(test.worker_count, worker, report, &test);
    ASSERT_NE(mtest, NULL);

    mtest_run(mtest);

    if (fail_err != 0) {
        printf("fail_err %d, fail_line %d\n", fail_err, fail_line);
        ASSERT_EQ(0, -1);
    }
    dt_destroy(tree);
    free(test.worker);
}

MTF_END_UTEST_COLLECTION(data_tree)
