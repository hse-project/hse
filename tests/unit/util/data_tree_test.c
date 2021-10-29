/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <mtf/common.h>

#include <hse_util/data_tree.h>

#include "multithreaded_tester.h"

int
platform_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PRE(data_tree, platform_pre);

struct test_element {
    int num;
};

static int test_element_remove_handler_hit;
static int test_element_emit_handler_hit;
static int test_element_set_handler_hit;

void
clear_handler_counts(void)
{
    test_element_emit_handler_hit = 0;
    test_element_set_handler_hit = 0;
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

struct dt_element_ops test_element_ops = {
    .dto_remove = test_element_remove_handler,
    .dto_emit = test_element_emit_handler,
    .dto_set = test_element_set_handler,
};

struct dt_element_ops test_element_alt_ops = {
    .dto_remove = test_element_remove_handler,
    .dto_emit = test_element_alt_emit_handler,
    .dto_set = test_element_set_handler,
};

MTF_DEFINE_UTEST(data_tree, tree_create_and_add)
{
    int                  rc;
    struct dt_element *  element;
    struct test_element *te;

    /* Now add a test_element */
    element = calloc(1, sizeof(*element));
    ASSERT_NE(element, NULL);

    te = calloc(1, sizeof(*te));
    ASSERT_NE(te, NULL);

    snprintf(element->dte_path, sizeof(element->dte_path), "%s/test_element/one", DT_PATH_TEST);
    element->dte_data = te;
    element->dte_ops = &test_element_ops;
    element->dte_type = DT_TYPE_TEST_ELEMENT;

    rc = dt_add(NULL);
    ASSERT_EQ(rc, EINVAL);

    rc = dt_add(element);
    ASSERT_EQ(rc, 0);

    rc = dt_add(element);
    ASSERT_EQ(rc, EEXIST);

    dt_remove_recursive(DT_PATH_TEST);
}

static struct dt_element *
add_test_element(char *path, int num)
{
    struct dt_element *  element;
    struct test_element *te;

    element = calloc(1, sizeof(*element));

    te = calloc(1, sizeof(*te));

    snprintf(element->dte_path, sizeof(element->dte_path), "%s%s", DT_PATH_TEST, path);
    element->dte_data = te;
    element->dte_ops = &test_element_ops;
    element->dte_type = DT_TYPE_TEST_ELEMENT;
    te->num = num;

    dt_add(element);

    return element;
}

#define TEST_ELEMENT_OPS_BUF_SIZE 4096
MTF_DEFINE_UTEST(data_tree, test_element_ops_function)
{
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

    /* Now add a test_element */
    element = add_test_element("/test_element/one", 1);

    buf = calloc(TEST_ELEMENT_OPS_BUF_SIZE, 1);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = TEST_ELEMENT_OPS_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Test Emit Handler */
    ret = element->dte_ops->dto_emit(element, &yc);

    ASSERT_EQ(test_element_emit_handler_hit, 1);
    ASSERT_EQ(yc.yaml_offset, FIXED_EMIT_SIZE);

    /* Test Set Handler */
    ret = element->dte_ops->dto_set(element, &dsp);
    ASSERT_EQ(test_element_set_handler_hit, 1);

    /* Test Remove Handler */
    ret = dt_remove(element);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(test_element_remove_handler_hit, 1);

    dt_remove_recursive(DT_PATH_TEST);

    free(buf);
}

#define TEST_ELEMENT_OPS_SHORT_BUF_SIZE 128
MTF_DEFINE_UTEST(data_tree, test_emit_overflow_protection)
{
    struct dt_element * element[3];
    struct yaml_context yc = {
        .yaml_offset = 0, .yaml_indent = 0,
    };
    union dt_iterate_parameters dip = {.yc = &yc };
    char *                      buf;
    int                         i;

    clear_handler_counts();

    /* Now add several test_elements */
    for (i = 0; i < 3; i++) {
        char name[32];

        snprintf(name, sizeof(name), "/test%d", i);
        element[i] = add_test_element(name, 1);
        ASSERT_NE(element[i], NULL);
    }

    buf = calloc(TEST_ELEMENT_OPS_SHORT_BUF_SIZE, 1);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = TEST_ELEMENT_OPS_SHORT_BUF_SIZE;
    yc.yaml_emit = NULL;

    /* Try to overflow */
    dt_iterate_cmd(DT_OP_EMIT, DT_PATH_TEST, &dip, NULL, NULL, NULL);

    ASSERT_EQ(yc.yaml_offset, TEST_ELEMENT_OPS_SHORT_BUF_SIZE);

    dt_remove_recursive(DT_PATH_TEST);

    free(buf);
}

MTF_DEFINE_UTEST(data_tree, test_find)
{
    struct dt_element *element1, *element2, *element4;
    struct dt_element *found;

    clear_handler_counts();

    element1 = add_test_element("/test1/one", 1);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element("/test1/one/two", 2);
    ASSERT_NE(element2, NULL);

    element4 = add_test_element("/test1/one/two/three/four", 4);
    ASSERT_NE(element4, NULL);

    /* Find each element by exact search */
    found = dt_find(DT_PATH_TEST "/test1/one", 1);
    ASSERT_EQ(found, element1);

    found = dt_find(DT_PATH_TEST "/test1/one/two", 1);
    ASSERT_EQ(found, element2);

    found = dt_find(DT_PATH_TEST "/test1/one/two/three/four", 1);
    ASSERT_EQ(found, element4);

    /* Try to find 'three' and prove that exact search doesn't find it */
    found = dt_find(DT_PATH_TEST "/test1/one/two/three", 1);
    ASSERT_EQ(found, NULL);

    /* Now find element4 with a fuzzy search starting at '.../three' */
    found = dt_find(DT_PATH_TEST "/test1/one/two/three", 0);
    ASSERT_EQ(found, element4);

    dt_remove_recursive(DT_PATH_TEST);
}

MTF_DEFINE_UTEST(data_tree, test_iterate_with_command)
{
    struct dt_element *element0, *element1, *element2, *element4;
    int                ret;

    clear_handler_counts();

    element0 = add_test_element("/test1", 0);
    ASSERT_NE(element0, NULL);

    element1 = add_test_element("/test1/one", 1);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element("/test1/one/two", 2);
    ASSERT_NE(element2, NULL);

    element4 = add_test_element("/test1/one/two/three/four", 4);
    ASSERT_NE(element4, NULL);

    /* Now iterate starting at the top and make sure you see
     * four elements (root + the 3 new elements.
     */
    ret = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_TEST "/test1", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 4);

    /* Now iterate starting in the middle, should see two */
    ret = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_TEST "/test1/one/two", NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 2);

    dt_remove_recursive(DT_PATH_TEST);
}

static int
select_for_0(struct dt_element *element)
{
    struct test_element *te = element->dte_data;

    return (te && te->num == 0) ? 1 : 0;
}

static int
select_for_1(struct dt_element *element)
{
    struct test_element *te = element->dte_data;

    return (te && te->num == 1) ? 1 : 0;
}

MTF_DEFINE_UTEST(data_tree, test_selection_callback)
{
    struct dt_element *element1, *element2, *element3, *element4;
    int                ret;

    clear_handler_counts();

    element1 = add_test_element("/one", 0);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element("/two", 1);
    ASSERT_NE(element2, NULL);

    element3 = add_test_element("/three", 1);
    ASSERT_NE(element3, NULL);

    element4 = add_test_element("/four", 1);
    ASSERT_NE(element4, NULL);

    /* Now, select for (te->num == 1)
     */
    ret = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_TEST, NULL, select_for_0, NULL, NULL);
    ASSERT_EQ(ret, 1);

    ret = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_TEST, NULL, select_for_1, NULL, NULL);
    ASSERT_EQ(ret, 3);

    dt_remove_recursive(DT_PATH_TEST);
}

MTF_DEFINE_UTEST(data_tree, test_iterate)
{
    struct dt_element *element[4];
    struct dt_element *found;
    int                found_count;

    clear_handler_counts();

    element[0] = add_test_element("/a", 1);
    ASSERT_NE(element[0], NULL);

    element[1] = add_test_element("/a/b", 1);
    ASSERT_NE(element[1], NULL);

    element[2] = add_test_element("/a/b/d", 1);
    ASSERT_NE(element[2], NULL);

    element[3] = add_test_element("/a/c", 1);
    ASSERT_NE(element[3], NULL);

    /* Should find all 4 elements plus the root if I start at /test */
    found_count = 0;
    found = NULL;
    do {
        found = dt_iterate_next(DT_PATH_TEST "/a", found);
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
        found = dt_iterate_next(DT_PATH_TEST "/a/b", found);
        if (found) {
            ASSERT_EQ(found, element[found_count + 1]);
            found_count++;
        }
    } while (found != NULL);

    ASSERT_EQ(found_count, 2);

    dt_remove_recursive(DT_PATH_TEST);
}

/* Start Test: multi-writer, no reader */
struct mtest *mtest;

#define WORK_TYPE_ADD 0x1
#define WORK_TYPE_DEL 0x2
#define WORK_TYPE_FIND 0x4
#define WORK_TYPE_ITER 0x8

struct test_worker {
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
    int                ret;

    element = add_test_element("/A/one", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element("/A/two", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element("/A/B/three", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element("/A/B/four", 1);
    ASSERT_NE(element, NULL);

    element = add_test_element("/C/five", 1);
    ASSERT_NE(element, NULL);

    /* Now iterate starting at the top and make sure you see six elements */
    ret = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_TEST, NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 5);

    /* Now recursively remove the /test/A sub-tree */
    ret = dt_remove_recursive(DT_PATH_TEST "/A");
    ASSERT_EQ(ret, 0);

    /* Now there should be two items left */
    ret = dt_iterate_cmd(DT_OP_COUNT, DT_PATH_TEST, NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, 1);

    dt_remove_recursive(DT_PATH_TEST);
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

                sprintf(dte->dte_path, "%s/worker%d/node%d", DT_PATH_TEST, id, i);
                dte->dte_ops = &test_element_alt_ops;
                dte->dte_type = DT_TYPE_DONT_CARE;
                dt_add(dte);
            }
        }
        if (work->work_type & WORK_TYPE_FIND) {
            for (i = 0; i < work->count_per_loop; i++) {
                char path[DT_PATH_MAX];

                sprintf(path, "%s/worker%d/node%d", DT_PATH_TEST, id, i);
                dte = dt_find(path, 1);
                if (!dte) {
                    fail_line = __LINE__;
                    fail_err = ENOENT;
                    return;
                }
            }
        }
        if (work->work_type & WORK_TYPE_ITER) {
            char   path[DT_PATH_MAX];
            char * buf;
            size_t buf_sz;
            size_t iter_count = 0;

            buf_sz = (work->count_per_loop + 1) * sizeof(path);
            buf = calloc(1, buf_sz);
            yc.yaml_buf = buf;
            yc.yaml_buf_sz = buf_sz;
            yc.yaml_emit = NULL;

            sprintf(path, "%s/worker%d", DT_PATH_TEST, id);
            iter_count = dt_iterate_cmd(DT_OP_EMIT, path, &dip, NULL, NULL, NULL);
            /* Plus 1 for root (i.e. "/test" */
            if (iter_count != work->count_per_loop) {
                fail_line = __LINE__;
                fail_err = EINVAL;
                return;
            }
            free(buf);
        }
        if (work->work_type & WORK_TYPE_DEL) {
            char path[DT_PATH_MAX];

            sprintf(path, "%s/worker%d", DT_PATH_TEST, id);
            found = dt_iterate_next(path, NULL);
            do {
                prev = found;
                if (prev == NULL) {
                    /* There is an error here, this should not be needed, we should
                     * break at the while(). But we are not.
                     */
                    break;
                }
                found = dt_iterate_next(path, found);
                dt_remove(prev);
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
    struct test     test;
    int             worker_count = 5;
    int             per_worker_count = 1000;
    int             i;

    clear_handler_counts();

    /* Test will have two WRITER_ADDER workers */
    test.worker = calloc(worker_count, sizeof(*test.worker));
    ASSERT_NE(test.worker, NULL);

    for (i = 0; i < worker_count; i++) {
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

    dt_remove_recursive(DT_PATH_TEST);
    free(test.worker);
}

MTF_END_UTEST_COLLECTION(data_tree)
