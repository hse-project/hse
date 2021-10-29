/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/slab.h>
#include <hse_util/hse_err.h>

#include <hse_util/yaml.h>
#include <hse_util/string.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(yaml);

enum test_mix_type {
    Test_Mix_Type_Invalid,
    Test_Mix_Type_Element_Type,
    Test_Mix_Type_Element,
    Test_Mix_Type_Element_Field,
    Test_Mix_Type_Element_List,
};

struct test_mix {
    enum test_mix_type type;
    char *             key;
    char *             value;
    struct test_mix *  next;
};

struct test_mix *
new_test_mix(struct test_mix *list, enum test_mix_type type, char *key, char *value)
{
    struct test_mix *tm, *next;

    tm = calloc(1, sizeof(*tm));
    if (tm == NULL) {
        /* Should probably be an ASSERT of some sort,
         * but it will be caught at the next level up.
         */
        return NULL;
    }

    tm->type = type;
    tm->key = key;
    tm->value = value;

    if (list == NULL) {
        /* This will be the first item in the list. */
        list = tm;
    } else {
        next = list;
        while (next->next) {
            /* We have to append to the list, so find the last
             * valid entry.
             */
            next = next->next;
        }
        next->next = tm;
    }
    return list;
}

int
compare_to_newline(char *buf, size_t *offset, char *string)
{
    int   i = 0;
    char *b = buf + *offset;

    if (!buf || !string) {
        /* Catch NULL pointer case */
        return -1;
    }
    while (*b && *string && (*b == *string)) {
        i++;
        if (*b == '\n') {
            /* We are only comparing lines, so break on '\n' */
            break;
        }
        b++;
        string++;
    }
    if (*b != *string) {
        /* Miscompare */
        return -1;
    }
    *offset += i;
    return 0;
}

#define MAX_LINE_SIZE 200
int
validate_buf(char *buf, size_t buf_sz, struct test_mix *list)
{
    char *             string;
    struct test_mix *  tm = list;
    enum test_mix_type prev = Test_Mix_Type_Invalid;
    int                current_indent = 0;
    int                i;
    size_t             offset = 0;
    size_t             main_offset = 0;
    int                ret;

    string = malloc(MAX_LINE_SIZE);
    if (string == NULL) {
        /* Really should be an ASSERT of some sort here.
         * But it will be caught at the next level up.
         */
        return -ENOMEM;
    }

    /* Iterate through the list, composing and then comparing one
     * line at a time.
     */
    while (tm) {
        memset(string, 0, MAX_LINE_SIZE);
        offset = 0;

        switch (tm->type) {
            case Test_Mix_Type_Invalid:
            default:
                goto error;
            case Test_Mix_Type_Element_Type:
                switch (prev) {
                    case Test_Mix_Type_Invalid:
                        current_indent = 0;
                        break;
                    case Test_Mix_Type_Element_Type:
                        current_indent++;
                        break;
                    case Test_Mix_Type_Element:
                        current_indent--;
                        break;
                    case Test_Mix_Type_Element_Field:
                    case Test_Mix_Type_Element_List:
                        current_indent--;
                        break;
                };
                /* Indent */
                for (i = 0; i < current_indent; i++) {
                    /* Every loop inserts _two_ spaces */
                    offset += sprintf(string + offset, "  ");
                }
                /* Body */
                offset += sprintf(string + offset, "%s:\n", tm->key);
                break;
            case Test_Mix_Type_Element:
                switch (prev) {
                    case Test_Mix_Type_Invalid:
                        /* Invalid */
                        goto error;
                    case Test_Mix_Type_Element_Type:
                        break;
                    case Test_Mix_Type_Element:
                        current_indent--;
                        break;
                    case Test_Mix_Type_Element_Field:
                    case Test_Mix_Type_Element_List:
                        current_indent--;
                        break;
                };
                /* Indent */
                for (i = 0; i < current_indent; i++) {
                    /* Every loop inserts _two_ spaces. */
                    offset += sprintf(string + offset, "  ");
                }
                /* Body */
                offset += sprintf(string + offset, "- %s: %s\n", tm->key, tm->value);
                current_indent++;
                break;
            case Test_Mix_Type_Element_Field:
            case Test_Mix_Type_Element_List:
                switch (prev) {
                    case Test_Mix_Type_Invalid:
                    case Test_Mix_Type_Element_Type:
                        /* Invalid */
                        goto error;
                    case Test_Mix_Type_Element:
                        break;
                    case Test_Mix_Type_Element_Field:
                    case Test_Mix_Type_Element_List:
                        break;
                };
                /* Indent */
                for (i = 0; i < current_indent; i++) {
                    /* Each loop inserts _two_ spaces. */
                    offset += sprintf(string + offset, "  ");
                }
                /* Body */
                if (tm->type == Test_Mix_Type_Element_Field)
                    offset += sprintf(string + offset, "%s: %s\n", tm->key, tm->value);
                else
                    offset += sprintf(string + offset, "- %s\n", tm->key);
                break;
        }
        ret = compare_to_newline(buf, &main_offset, string);
        if (ret != 0) {
            /* Miscompare */
            goto error;
        }
        prev = tm->type;
        tm = tm->next;
    }
    free(string);
    return 0;

error:
    free(string);
    return -1;
}

void
delete_test_list(struct test_mix *list)
{
    struct test_mix *tm = list, *next;

    while (tm) {
        next = tm->next;
        free(tm);
        tm = next;
    }
}

#define DEFAULT_BUF_SZ 4096

/* 1. Test adding a single element type
 */
MTF_DEFINE_UTEST(yaml, yaml_single_element_type)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    /* End an element_type without any previous context */
    yaml_end_element_type(&yc);
    ASSERT_EQ(0, yc.yaml_indent);

    /* End an element without any previous context */
    yaml_end_element(&yc);
    ASSERT_EQ(0, yc.yaml_indent);

    yaml_start_element_type(&yc, "data");

    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 2. Test adding a single element type with another element type after.
 */
MTF_DEFINE_UTEST(yaml, yaml_successive_element_types)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 3. Test adding a single element after two element types
 */
MTF_DEFINE_UTEST(yaml, yaml_first_element)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    yaml_start_element(&yc, "path", "/woo/boo/hoo");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element, "path", "/woo/boo/hoo");

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    yaml_end_element(&yc);
    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 4. Test adding a single element field to an element
 */
MTF_DEFINE_UTEST(yaml, yaml_first_element_field)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;
    int              ind;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    /* There's no element context to end. */
    ind = yc.yaml_indent;
    yaml_end_element(&yc);
    ASSERT_EQ(ind, yc.yaml_indent);

    yaml_start_element(&yc, "path", "/woo/boo/hoo");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element, "path", "/woo/boo/hoo");

    yaml_element_field(&yc, "odometer", "1");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Field, "odometer", "1");

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    /* The previous element context hasn't ended */
    ind = yc.yaml_indent;
    yaml_end_element_type(&yc);
    ASSERT_EQ(ind, yc.yaml_indent);

    yaml_end_element(&yc);
    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 5. Test adding an element type after an element
 */
MTF_DEFINE_UTEST(yaml, yaml_element_type_after_element)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    yaml_start_element(&yc, "path", "/woo/boo/hoo");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element, "path", "/woo/boo/hoo");
    yaml_end_element(&yc);

    yaml_start_element_type(&yc, "performance_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "performance_counter", NULL);

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 6. Test adding an element type after an element field
 */
MTF_DEFINE_UTEST(yaml, yaml_element_type_after_element_field)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    yaml_start_element(&yc, "path", "/woo/boo/hoo");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element, "path", "/woo/boo/hoo");

    yaml_element_field(&yc, "fname", "value");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Field, "fname", "value");

    yaml_end_element(&yc);
    yaml_end_element_type(&yc);

    yaml_start_element_type(&yc, "performance_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "performance_counter", NULL);

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 7. Test adding a single element list to an element
 */
MTF_DEFINE_UTEST(yaml, yaml_first_element_list)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;
    int              ind;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    /* There's no element context to end. */
    ind = yc.yaml_indent;
    yaml_end_element(&yc);
    ASSERT_EQ(ind, yc.yaml_indent);

    yaml_start_element(&yc, "path", "/woo/boo/hoo");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element, "path", "/woo/boo/hoo");

    yaml_element_list(&yc, "milk");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_List, "milk", 0);

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    /* The previous element context hasn't ended */
    ind = yc.yaml_indent;
    yaml_end_element_type(&yc);
    ASSERT_EQ(ind, yc.yaml_indent);

    yaml_end_element(&yc);
    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/* 8. Test adding an element type after an element field
 */
MTF_DEFINE_UTEST(yaml, yaml_element_type_after_element_list)
{
    char *              buf;
    struct yaml_context yc = {
        .yaml_indent = 0, .yaml_offset = 0,
    };
    struct test_mix *test_list = NULL;
    int              ret;

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);
    yc.yaml_buf = buf;
    yc.yaml_buf_sz = DEFAULT_BUF_SZ;
    yc.yaml_emit = NULL;

    yaml_start_element_type(&yc, "data");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "data", NULL);

    yaml_start_element_type(&yc, "event_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "event_counter", NULL);

    yaml_start_element(&yc, "path", "/woo/boo/hoo");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element, "path", "/woo/boo/hoo");

    yaml_element_list(&yc, "fname");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_List, "fname", 0);

    yaml_end_element(&yc);
    yaml_end_element_type(&yc);

    yaml_start_element_type(&yc, "performance_counter");
    test_list = new_test_mix(test_list, Test_Mix_Type_Element_Type, "performance_counter", NULL);

    ret = validate_buf(buf, DEFAULT_BUF_SZ, test_list);
    ASSERT_EQ(ret, 0);

    yaml_end_element_type(&yc);
    yaml_end_element_type(&yc);

    delete_test_list(test_list);
    free(buf);
}

/*
 * 9. Test yaml_emit_and_rewind()
 */
MTF_DEFINE_UTEST(yaml, yaml_emit_and_rewind_test)
{
#define BUFSZ 128
    char                line[16];
    int                 i, j;
    struct yaml_context yc = {
        .yaml_prev = Yaml_Context_Type_Invalid, .yaml_indent = 0, .yaml_offset = 0,
    };

    line[14] = '\0';

    yc.yaml_buf = malloc(BUFSZ);
    yc.yaml_buf_sz = BUFSZ;
    yc.yaml_emit = yaml_realloc_buf;

    for (i = 0; i < 16; i++) {
        /*
         * Fill in first 14 characters,yaml_start_element_type()
         * will fill in the 14th (:) and 15th (\n)
         */
        for (j = 0; j < 14; j++)
            line[j] = (char)(i + j + 1);
        yaml_start_element_type(&yc, line);
        yaml_end_element_type(&yc);
    }

    for (i = 0; i < 16; i++) {
        for (j = 0; j < 14; j++)
            ASSERT_EQ((char)(i + j + 1), yc.yaml_buf[i * 16 + j]);
        ASSERT_EQ(':', yc.yaml_buf[i * 16 + 14]);
        ASSERT_EQ('\n', yc.yaml_buf[i * 16 + 15]);
    }

    free(yc.yaml_buf);
}
MTF_END_UTEST_COLLECTION(yaml)
