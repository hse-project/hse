/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse_util/json.h>
#include <hse_util/string.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(json);

struct example {
    char *desc;
    int   cnt;
};

void
example_cb(const void *data, int index, char *buf, size_t buf_sz)
{
    struct example *ex = (struct example *)data + index;

    snprintf(buf, buf_sz, "%s_%d", ex->desc, ex->cnt);
}

MTF_DEFINE_UTEST(json, json_invalid_usage)
{
    char                buf[64] = "";
    int                 argc = 3;
    int                 argv[3] = { 1, 2, 3 };
    struct json_context jc = { 0 };

    jc.json_buf = buf;
    jc.json_buf_sz = sizeof(buf);

    json_element_start(&jc, "test");
    ASSERT_EQ(strcmp(buf, ""), 0);

    json_element_field(&jc, "hello", "%s", "world");
    ASSERT_EQ(strcmp(buf, ""), 0);

    json_element_list(&jc, "content", "%d", argc, argv);
    ASSERT_EQ(strcmp(buf, ""), 0);

    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, ""), 0);
}

MTF_DEFINE_UTEST(json, json_basic_usage)
{
    char                buf[64], cmp[64];
    int                 pos = 0;
    int                 argc = 3;
    int                 argv[3] = { 1, 2, 3 };
    struct json_context jc = { 0 };

    jc.json_buf = buf;
    jc.json_buf_sz = sizeof(buf);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "{");
    json_element_start(&jc, 0);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "\"hello\":\"world\",");
    json_element_field(&jc, "hello", "%s", "world");
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "\"content\":[1,2,3],");
    json_element_list(&jc, "content", "%d", argc, argv);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    snprintf(cmp + pos - 1, sizeof(cmp) - pos + 1, "%s", "}");
    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);
}

MTF_DEFINE_UTEST(json, json_nested_field)
{
    char                buf[64], cmp[64];
    int                 pos = 0;
    struct json_context jc = { 0 };

    jc.json_buf = buf;
    jc.json_buf_sz = sizeof(buf);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "{");
    json_element_start(&jc, 0);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "\"child1\":{");
    json_element_start(&jc, "child1");
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "\"depth\":1,");
    json_element_field(&jc, "depth", "%d", 1);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "\"child2\":{");
    json_element_start(&jc, "child2");
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "\"depth\":2,");
    json_element_field(&jc, "depth", "%d", 2);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos - 1, sizeof(cmp) - pos + 1, "%s", "},") - 1;
    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos - 1, sizeof(cmp) - pos + 1, "%s", "},") - 1;
    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    snprintf(cmp + pos - 1, sizeof(cmp) - pos + 1, "%s", "}");
    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);
}

MTF_DEFINE_UTEST(json, json_custom_list)
{
    char                buf[64];
    int                 argc = 3;
    struct example      argv[3] = { { "a", 1 }, { "b", 2 }, { "c", 3 } };
    struct json_context jc = { 0 };

    jc.json_buf = buf;
    jc.json_buf_sz = sizeof(buf);

    json_element_start(&jc, 0);
    json_element_list_custom(&jc, "content", &example_cb, argc, argv);
    json_element_end(&jc);

    ASSERT_EQ(strcmp(buf, "{\"content\":[a_1,b_2,c_3]}"), 0);
}

MTF_DEFINE_UTEST(json, json_field_fmt)
{
    char                buf[128], cmp[128];
    int                 pos = 0;
    struct json_context jc = { 0 };

    jc.json_buf = buf;
    jc.json_buf_sz = sizeof(buf);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "{");
    json_element_start(&jc, 0);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"string\":\"%s\",", "abcdef");
    json_element_field(&jc, "string", "%s", "abcdef");
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"number\":%d,", 42);
    json_element_field(&jc, "number", "%d", 42);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"hex\":\"%x\",", 1024);
    json_element_field(&jc, "hex", "%x", 1024);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"pointer\":\"%p\",", &buf);
    json_element_field(&jc, "pointer", "%p", &buf);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    snprintf(cmp + pos - 1, sizeof(cmp) - pos + 1, "%s", "}");
    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);
}

MTF_DEFINE_UTEST(json, json_list_fmt)
{
    char                buf[128], cmp[128];
    int                 pos = 0;
    struct json_context jc = { 0 };

    char *        list_1[2] = { "cat", "dog" };
    int           list_2[2] = { 764, 5663 };
    unsigned long list_3[2] = { 4843454565, 8656934565 };

    jc.json_buf = buf;
    jc.json_buf_sz = sizeof(buf);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "%s", "{");
    json_element_start(&jc, 0);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    /* supported formats */

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"pets\":[\"cat\",\"dog\"],");
    json_element_list(&jc, "pets", "%s", 2, list_1);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"seconds\":[764,5663],");
    json_element_list(&jc, "seconds", "%d", 2, list_2);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"money\":[4843454565,8656934565],");
    json_element_list(&jc, "money", "%lu", 2, list_3);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    /* unsupported formats */

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"hex\":[],");
    json_element_list(&jc, "hex", "%x", 2, list_2);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    pos += snprintf(cmp + pos, sizeof(cmp) - pos, "\"pointer\":[],");
    json_element_list(&jc, "pointer", "%p", 2, list_2);
    ASSERT_EQ(strcmp(buf, cmp), 0);

    snprintf(cmp + pos - 1, sizeof(cmp) - pos, "%s", "}");
    json_element_end(&jc);
    ASSERT_EQ(strcmp(buf, cmp), 0);
}

MTF_END_UTEST_COLLECTION(json)
