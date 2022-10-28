/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>

#include <hse/util/slab.h>
#include <hse/error/merr.h>
#include <hse/util/printbuf.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(printbuf);

#define DEFAULT_BUF_SZ 4096
#define DEFAULT_STRING_SZ 50
#define DEFAULT_BUF_VAL 1
#define DEFAULT_STRING_VAL 2

/**
 * test_for - validate a region of a buffer,
 * @buf    - char *, buffer to be tested
 * @val    - unsigned char, value to be compared for
 * @offset - size_t, starting point in the buf
 * @len    - size_t, number of bytes to test
 *
 * starting at @offset, for * length @len, compare for @val.
 *
 * Return: -1 (success) or a value of 0 or more indicate buffer position
 * that failed to compare. Yes, -1 is a strange success value, but using
 * it means that I can return the buffer position that failed, which can
 * be useful.
 */
int
test_for(char *buf, unsigned char val, size_t offset, size_t len)
{
    int i;

    for (i = 0; i < len; i++) {
        if (*(buf + i + offset) != val) {
            /* Miscompare, return the position */
            return i;
        }
    }
    return -1;
}

/* 1. Test adding a single string with sprintbuf */
MTF_DEFINE_UTEST(printbuf, sprintbuf_single)
{
    char * buf;
    size_t offset;
    size_t remaining;
    char * string;
    int    ret;

    string = calloc(1, DEFAULT_STRING_SZ + 1);
    ASSERT_NE(string, NULL);

    memset(string, DEFAULT_STRING_VAL, DEFAULT_STRING_SZ);

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);

    memset(buf, DEFAULT_BUF_VAL, DEFAULT_BUF_SZ);
    remaining = DEFAULT_BUF_SZ;
    offset = 0;

    sprintbuf(buf, &remaining, &offset, "%s", string);

    ASSERT_EQ(DEFAULT_BUF_SZ - remaining, offset);

    ret = test_for(buf, DEFAULT_STRING_VAL, 0, DEFAULT_STRING_SZ);
    ASSERT_EQ(ret, -1);

    /* The '+1' and '-1' in the test_for below are to deal with
     * the '\0' that vsnprintf is appending to the end of the
     * string when it is printed into the buffer.
     */
    ret = test_for(
        buf, DEFAULT_BUF_VAL, DEFAULT_STRING_SZ + 1, DEFAULT_BUF_SZ - DEFAULT_STRING_SZ - 1);
    ASSERT_EQ(ret, -1);

    free(buf);
    free(string);
}

/* 2. Test adding a single entry with snprintf_append */
MTF_DEFINE_UTEST(printbuf, snprintf_append_single)
{
    char * buf;
    size_t offset;
    char * string;
    int    ret;

    string = calloc(1, DEFAULT_STRING_SZ + 1);
    ASSERT_NE(string, NULL);

    memset(string, DEFAULT_STRING_VAL, DEFAULT_STRING_SZ);

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);

    memset(buf, DEFAULT_BUF_VAL, DEFAULT_BUF_SZ);
    offset = 0;

    snprintf_append(buf, DEFAULT_BUF_SZ, &offset, string);

    ret = test_for(buf, DEFAULT_STRING_VAL, 0, DEFAULT_STRING_SZ);
    ASSERT_EQ(ret, -1);

    /* The '+1' and '-1' in the test_for below are to deal with
     * the '\0' that vsnprintf is appending to the end of the
     * string when it is printed into the buffer.
     */
    ret = test_for(
        buf, DEFAULT_BUF_VAL, DEFAULT_STRING_SZ + 1, DEFAULT_BUF_SZ - DEFAULT_STRING_SZ - 1);
    ASSERT_EQ(ret, -1);

    free(buf);
    free(string);
}

#define SHORT_BUF_SZ 20
#define SHORT_BUF_OFFSET 100

/* 3. Test overflow handling of sprintbuf */
MTF_DEFINE_UTEST(printbuf, sprintbuf_overflow)
{
    char * buf, *short_buf;
    size_t offset;
    size_t remaining;
    char * string;
    int    ret;

    string = calloc(1, DEFAULT_STRING_SZ + 1);
    ASSERT_NE(string, NULL);

    memset(string, DEFAULT_STRING_VAL, DEFAULT_STRING_SZ);

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);

    memset(buf, DEFAULT_BUF_VAL, DEFAULT_BUF_SZ);

    short_buf = buf + SHORT_BUF_OFFSET;
    remaining = SHORT_BUF_SZ;
    offset = 0;

    sprintbuf(short_buf, &remaining, &offset, "%s", string);

    ASSERT_EQ(remaining, 0);

    ret = test_for(buf, DEFAULT_BUF_VAL, 0, SHORT_BUF_OFFSET);
    ASSERT_EQ(ret, -1);

    ret = test_for(buf, DEFAULT_STRING_VAL, SHORT_BUF_OFFSET, SHORT_BUF_SZ - 1);
    ASSERT_EQ(ret, -1);

    /* The '+1' and '-1' in the test_for below are to deal with
     * the '\0' that vsnprintf is appending to the end of the
     * string when it is printed into the buffer.
     */
    ret = test_for(
        buf,
        DEFAULT_BUF_VAL,
        SHORT_BUF_OFFSET + SHORT_BUF_SZ,
        DEFAULT_BUF_SZ - SHORT_BUF_OFFSET - SHORT_BUF_SZ - 1);
    ASSERT_EQ(ret, -1);

    free(buf);
    free(string);
}

/* 4. Test overflow handling of snprintf_append */
MTF_DEFINE_UTEST(printbuf, snprintf_append_overflow)
{
    char * buf, *short_buf;
    size_t offset;
    char * string;
    int    ret;

    string = calloc(1, DEFAULT_STRING_SZ + 1);
    ASSERT_NE(string, NULL);

    memset(string, DEFAULT_STRING_VAL, DEFAULT_STRING_SZ);

    buf = calloc(1, DEFAULT_BUF_SZ);
    ASSERT_NE(buf, NULL);

    memset(buf, DEFAULT_BUF_VAL, DEFAULT_BUF_SZ);

    short_buf = buf + SHORT_BUF_OFFSET;
    offset = 0;

    snprintf_append(short_buf, SHORT_BUF_SZ, &offset, "%s", string);

    ret = test_for(buf, DEFAULT_BUF_VAL, 0, SHORT_BUF_OFFSET);
    ASSERT_EQ(ret, -1);

    ret = test_for(buf, DEFAULT_STRING_VAL, SHORT_BUF_OFFSET, SHORT_BUF_SZ - 1);
    ASSERT_EQ(ret, -1);

    /* The '+1' and '-1' in the test_for below are to deal with
     * the '\0' that vsnprintf is appending to the end of the
     * string when it is printed into the buffer.
     */
    ret = test_for(
        buf,
        DEFAULT_BUF_VAL,
        SHORT_BUF_OFFSET + SHORT_BUF_SZ,
        DEFAULT_BUF_SZ - SHORT_BUF_OFFSET - SHORT_BUF_SZ - 1);
    ASSERT_EQ(ret, -1);

    free(buf);
    free(string);
}

MTF_DEFINE_UTEST(printbuf, strlcpy_append_test)
{
    const char *src1 = "abc";
    char        dst1[8];
    size_t      offset;
    int         cc;

    /* strlcpy_append() with overrun...
     */
    offset = 0;
    cc = strlcpy_append(dst1, src1, sizeof(dst1), &offset);
    ASSERT_EQ(strlen(src1), cc);
    ASSERT_EQ(strlen(src1), offset);

    cc = strlcpy_append(dst1, src1, sizeof(dst1), &offset);
    ASSERT_EQ(strlen(src1), cc);
    ASSERT_EQ(strlen(src1) * 2, offset);

    cc = strlcpy_append(dst1, src1, sizeof(dst1), &offset);
    ASSERT_EQ(strlen(src1), cc);
    ASSERT_EQ(sizeof(dst1), offset);
}

/* Test u64_append() with/without width specification...
 */
MTF_DEFINE_UTEST(printbuf, u64_append_test)
{
    char   dst2[64], dst3[64];
    size_t offset;
    int    cc2, cc3;
    int    i;

    offset = 0;
    cc2 = u64_append(dst2, 8, U64_MAX, 0, &offset);
    ASSERT_EQ(0, cc2);

    offset = 0;
    cc2 = u64_append(dst2, sizeof(dst2), U64_MAX, 0, &offset);
    cc3 = snprintf(dst3, sizeof(dst3), "%lu", U64_MAX);
    ASSERT_EQ(cc2, cc3);
    ASSERT_EQ(cc3, offset);

    /* With a negative width prepend once space...
     */
    offset = 0;
    cc2 = u64_append(dst2, sizeof(dst2), U64_MAX, -1, &offset);
    cc3 = snprintf(dst3, sizeof(dst3), " %lu", U64_MAX);
    ASSERT_EQ(cc2, cc3);
    ASSERT_EQ(cc3, offset);

    for (i = 0; i < 7; ++i) {
        int width = 23 + i;

        offset = 0;
        cc2 = u64_append(dst2, sizeof(dst2), U64_MAX - width * 17, width, &offset);
        cc3 = snprintf(dst3, sizeof(dst3), "%*lu", width, U64_MAX - width * 17);
        ASSERT_EQ(cc2, cc3);
        ASSERT_EQ(cc3, offset);

        cc2 = u64_append(dst2, sizeof(dst2), U64_MAX - width * 17, 0, &offset);
        cc3 = snprintf(dst3 + cc3, sizeof(dst3) - cc3, "%lu", U64_MAX - width * 17);
        ASSERT_EQ(cc2, cc3);
        ASSERT_EQ(width + cc3, offset);

        ASSERT_EQ(0, strcmp(dst2, dst3));
    }
}

/* Test u64_to_string() with numbers throughout the range...
 */
MTF_DEFINE_UTEST(printbuf, u64_to_string_test)
{
    char dst2[64], dst3[64];
    int  cc2, cc3;
    int  i;

    cc2 = u64_to_string(dst2, 8, U64_MAX);
    ASSERT_EQ(cc2, 0);

    for (i = 0; i < 64; ++i) {
        u64 val = i > 0 ? (1UL << i) | i : 0;

        cc2 = u64_to_string(dst2, sizeof(dst2), val);
        cc3 = snprintf(dst3, sizeof(dst3), "%lu", val);

        ASSERT_EQ(cc2, cc3);
        ASSERT_EQ(0, strcmp(dst2, dst3));
    }
}

MTF_END_UTEST_COLLECTION(printbuf)
