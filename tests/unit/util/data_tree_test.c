/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <hse/util/data_tree.h>

#include <hse/test/mtf/common.h>
#include <hse/test/mtf/framework.h>

#include "multithreaded_tester.h"

#define DT_PATH_TEST "/data/test"

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(data_tree);

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

void
test_element_remove_handler(struct dt_element *element)
{
    test_element_remove_handler_hit++;
    if (element->dte_data) {
        /* Free the underlying data object */
        free(element->dte_data);
    }

    free(element);
}

merr_t
test_element_emit_handler(struct dt_element *element, cJSON *root)
{
    cJSON *elem;
    bool bad = false;

    elem = cJSON_CreateObject();
    if (!elem)
        return merr(ENOMEM);

    test_element_emit_handler_hit++;

    bad |= !cJSON_AddStringToObject(elem, "path", element->dte_path);
    bad |= !cJSON_AddItemToArray(root, elem);

    return bad ? merr(ENOMEM) : 0;
}

struct dt_element_ops test_element_ops = {
    .dto_remove = test_element_remove_handler,
    .dto_emit = test_element_emit_handler,
};

struct dt_element_ops test_element_alt_ops = {
    .dto_remove = test_element_remove_handler,
    .dto_emit = test_element_emit_handler,
};

MTF_DEFINE_UTEST(data_tree, tree_create_and_add)
{
    int rc;
    struct dt_element *element;
    struct test_element *te;

    /* Now add a test_element */
    element = calloc(1, sizeof(*element));
    ASSERT_NE(NULL, element);

    te = calloc(1, sizeof(*te));
    ASSERT_NE(te, NULL);

    snprintf(element->dte_path, sizeof(element->dte_path), "%s/test_element/one", DT_PATH_TEST);
    element->dte_data = te;
    element->dte_ops = &test_element_ops;

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
    struct dt_element *element;
    struct test_element *te;

    element = calloc(1, sizeof(*element));

    te = calloc(1, sizeof(*te));

    snprintf(element->dte_path, sizeof(element->dte_path), "%s%s", DT_PATH_TEST, path);
    element->dte_data = te;
    element->dte_ops = &test_element_ops;
    te->num = num;

    dt_add(element);

    return element;
}

MTF_DEFINE_UTEST(data_tree, test_element_ops_function)
{
    merr_t err;
    cJSON *root;
    struct dt_element *element;

    clear_handler_counts();

    /* Now add a test_element */
    element = add_test_element("/test_element/one", 1);
    ASSERT_NE(NULL, element);

    root = cJSON_CreateArray();
    ASSERT_NE(NULL, root);

    /* Test Emit Handler */
    err = element->dte_ops->dto_emit(element, root);

    ASSERT_EQ(test_element_emit_handler_hit, 1);
    ASSERT_EQ(1, cJSON_GetArraySize(root));

    /* Test Remove Handler */
    err = dt_remove(element->dte_path);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(1, test_element_remove_handler_hit);

    dt_remove_recursive(DT_PATH_TEST);

    cJSON_Delete(root);
}

MTF_DEFINE_UTEST(data_tree, test_emit_overflow_protection)
{
    merr_t err;
    cJSON *root;
    struct dt_element *element[3];

    clear_handler_counts();

    /* Now add several test_elements */
    for (int i = 0; i < 3; i++) {
        char name[32];

        snprintf(name, sizeof(name), "/test%d", i);
        element[i] = add_test_element(name, 1);
        ASSERT_NE(element[i], NULL);
    }

    /* Try to overflow */
    err = dt_emit(DT_PATH_TEST, &root);
    ASSERT_EQ(0, merr_errno(err));
    ASSERT_EQ(3, cJSON_GetArraySize(root));

    dt_remove_recursive(DT_PATH_TEST);

    cJSON_Delete(root);
}

MTF_DEFINE_UTEST(data_tree, test_find)
{
    merr_t err;
    struct dt_element *element1, *element2, *element4;

    clear_handler_counts();

    element1 = add_test_element("/test1/one", 1);
    ASSERT_NE(element1, NULL);

    element2 = add_test_element("/test1/one/two", 2);
    ASSERT_NE(element2, NULL);

    element4 = add_test_element("/test1/one/two/three/four", 4);
    ASSERT_NE(element4, NULL);

    /* Find each element by exact search */
    err = dt_access(DT_PATH_TEST "/test1/one", NULL, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = dt_access(DT_PATH_TEST "/test1/one/two", NULL, NULL);
    ASSERT_EQ(0, merr_errno(err));

    err = dt_access(DT_PATH_TEST "/test1/one/two/three/four", NULL, NULL);
    ASSERT_EQ(0, merr_errno(err));

    /* Try to find 'three' and prove that exact search doesn't find it */

    err = dt_access(DT_PATH_TEST "/test1/one/two/three", NULL, NULL);
    ASSERT_EQ(ENOENT, merr_errno(err));

    dt_remove_recursive(DT_PATH_TEST);
}

MTF_DEFINE_UTEST(data_tree, test_iterate_with_command)
{
    struct dt_element *element0, *element1, *element2, *element4;
    int ret;

    clear_handler_counts();

    element0 = add_test_element("/test1", 0);
    ASSERT_NE(NULL, element0);

    element1 = add_test_element("/test1/one", 1);
    ASSERT_NE(NULL, element1);

    element2 = add_test_element("/test1/one/two", 2);
    ASSERT_NE(NULL, element2);

    element4 = add_test_element("/test1/one/two/three/four", 4);
    ASSERT_NE(NULL, element4);

    /* Now iterate starting at the top and make sure you see
     * four elements (root + the 3 new elements.
     */
    ret = dt_count(DT_PATH_TEST "/test1");
    ASSERT_EQ(4, ret);

    /* Now iterate starting in the middle, should see two */
    ret = dt_count(DT_PATH_TEST "/test1/one/two");
    ASSERT_EQ(2, ret);

    dt_remove_recursive(DT_PATH_TEST);
}

/* Start Test: multi-writer, no reader */
struct mtest *mtest;

#define WORK_TYPE_ADD  0x1
#define WORK_TYPE_DEL  0x2
#define WORK_TYPE_FIND 0x4
#define WORK_TYPE_ITER 0x8

struct test_worker {
    uint32_t work_type;
    int count_per_loop;
    int loop_count;
};

struct test {
    int worker_count;
    struct mtf_test_info *lcl_ti;
    struct test_worker *worker;
};

MTF_DEFINE_UTEST(data_tree, remove_recursive)
{
    int ret;
    merr_t err;
    struct dt_element *element;

    element = add_test_element("/A/one", 1);
    ASSERT_NE(NULL, element);

    element = add_test_element("/A/two", 1);
    ASSERT_NE(NULL, element);

    element = add_test_element("/A/B/three", 1);
    ASSERT_NE(NULL, element);

    element = add_test_element("/A/B/four", 1);
    ASSERT_NE(NULL, element);

    element = add_test_element("/C/five", 1);
    ASSERT_NE(NULL, element);

    /* Now iterate starting at the top and make sure you see six elements */
    ret = dt_count(DT_PATH_TEST);
    ASSERT_EQ(5, ret);

    /* Now recursively remove the /test/A sub-tree */
    err = dt_remove_recursive(DT_PATH_TEST "/A");
    ASSERT_EQ(0, merr_errno(err));

    /* Now there should be two items left */
    ret = dt_count(DT_PATH_TEST);
    ASSERT_EQ(1, ret);

    dt_remove_recursive(DT_PATH_TEST);
}

static int fail_err;
static int fail_line;

static void
worker(void *context, int id)
{
    struct test *test = context;
    struct test_worker *work = &(test->worker[id]);
    struct dt_element *dte;

    mtest_barrier(mtest);

    for (int loop = 0; loop < work->loop_count; loop++) {
        if (work->work_type & WORK_TYPE_ADD) {
            for (int i = 0; i < test->worker[id].count_per_loop; i++) {
                dte = calloc(1, sizeof(*dte));
                if (!dte) {
                    fail_line = __LINE__;
                    fail_err = ENOMEM;
                    return;
                }

                sprintf(dte->dte_path, "%s/worker%d/node%d", DT_PATH_TEST, id, i);
                dte->dte_ops = &test_element_alt_ops;
                dt_add(dte);
            }
        }
        if (work->work_type & WORK_TYPE_FIND) {
            for (int i = 0; i < work->count_per_loop; i++) {
                merr_t err;
                char path[DT_PATH_MAX];

                snprintf(path, sizeof(path), "%s/worker%d/node%d", DT_PATH_TEST, id, i);

                err = dt_access(path, NULL, NULL);
                if (err) {
                    fail_line = __LINE__;
                    fail_err = ENOENT;
                    return;
                }
            }
        }
        if (work->work_type & WORK_TYPE_ITER) {
            size_t iter_count = 0;
            char path[DT_PATH_MAX];

            snprintf(path, sizeof(path), "%s/worker%d", DT_PATH_TEST, id);

            iter_count = dt_count(path);
            if (iter_count != work->count_per_loop) {
                printf("%lu %d\n", iter_count, work->count_per_loop);
                fail_line = __LINE__;
                fail_err = EINVAL;
                return;
            }
        }
        if (work->work_type & WORK_TYPE_DEL) {
            char path[DT_PATH_MAX];

            sprintf(path, "%s/worker%d", DT_PATH_TEST, id);

            dt_remove_recursive(path);
        }
    }
}

static void
report(void *context, double elapsed_time)
{
    struct test *test = (struct test *)context;
    int count = 0;

    /* Count up how many to expect */
    for (int i = 0; i < test->worker_count; i++) {
        count += test->worker[i].count_per_loop * test->worker[i].loop_count;
    }

    printf("%s: expected count %d\n", __func__, count);
}

MTF_DEFINE_UTEST(data_tree, multithreaded_stress)
{
    struct test test;
    int worker_count = 5;
    int per_worker_count = 1000;
    int i;

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
