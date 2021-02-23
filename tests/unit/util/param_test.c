/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>

#include <hse_util/slab.h>
#include <hse_util/page.h>
#include <hse_util/inttypes.h>
#include <hse_util/hse_err.h>
#include <hse_util/param.h>
#include <hse_util/parser.h>

int
param_test_pre(struct mtf_test_info *lcl_ti)
{
    return 0;
}

int
param_test_post(struct mtf_test_info *lcl_ti)
{
    return 0;
}

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION_PREPOST(param, param_test_pre, param_test_post);

/* 1. Basic test of using a match_table_t
 */
MTF_DEFINE_UTEST(param, example_match_table)
{
    int         ret;
    substring_t val;

    match_table_t params = { { 1, "mode=%s" },  { 2, "uid=%s" },    { 3, "gid=%d" },
                             { 4, "gid=%s" },   { 5, "total=%s" },  { 6, "total-%s" },
                             { 7, "total+%s" }, { 8, "mpname=%s" }, { -1, NULL } };

    ret = match_token("mpname=joe", params, &val);
    ASSERT_EQ(ret, 8);
    ASSERT_EQ(0, strcmp("joe", val.from));

    ret = match_token("MiamiVice", params, &val);
    ASSERT_EQ(ret, -1);

    ret = match_token("total=12M", params, &val);
    ASSERT_EQ(ret, 5);

    ret = match_token("total-12M", params, &val);
    ASSERT_EQ(ret, 6);

    ret = match_token("total+12M", params, &val);
    ASSERT_EQ(ret, 7);
}

#define PARAM_TYPE_MOE                                       \
    {                                                        \
        "moe=%d", sizeof(u32), 0, 0, get_u32, show_u32, NULL \
    }
#define PARAM_TYPE_CURLY                                       \
    {                                                          \
        "curly=%d", sizeof(u16), 0, 0, get_u16, show_u16, NULL \
    }
#define PARAM_TYPE_LARRY                                       \
    {                                                          \
        "larry=%d", sizeof(u64), 0, 0, get_u64, show_u64, NULL \
    }

/* 2. Test generating a match table
 */
MTF_DEFINE_UTEST(param, generate_match_table)
{
    merr_t              err;
    struct match_token *table;
    u32                 moe;
    u16                 curly;
    u64                 larry;
    int                 ret;
    substring_t         val;
    int                 entry_cnt;

    struct param_inst pi[] = { PARAM_INST(PARAM_TYPE_MOE, moe, "Moe Howard"),
                               PARAM_INST(PARAM_TYPE_CURLY, curly, "Curly Howard"),
                               PARAM_INST(PARAM_TYPE_LARRY, larry, "Larry Fine"),
                               PARAM_INST_END };

    err = param_gen_match_table(pi, &table, &entry_cnt);
    ASSERT_EQ(err, 0);

    ret = match_token("curly=12", table, &val);
    ASSERT_EQ(ret, 1);

    param_free_match_table(table);
}

/* Create a couple of param types */
#define PARAM_TYPE_ABC                                       \
    {                                                        \
        "abc=%d", sizeof(u32), 0, 0, get_u32, show_u32, NULL \
    }
#define PARAM_TYPE_DEF                                       \
    {                                                        \
        "def=%d", sizeof(u64), 0, 0, get_u64, show_u64, NULL \
    }
#define PARAM_TYPE_GHI                                    \
    {                                                     \
        "ghi=%s", 32, 0, 0, get_string, show_string, NULL \
    }
#define PARAM_TYPE_JKL                                          \
    {                                                           \
        "jkl=%s", sizeof(bool), 0, 0, get_bool, show_bool, NULL \
    }

/* 3. Process Parameters Test
 */
MTF_DEFINE_UTEST(param, process_params_test)
{
    u32    abc;
    u64    def;
    char   ghi[32];
    bool   jkl;
    merr_t err;
    int    next_arg = 0;

    struct param_inst pi[] = { PARAM_INST(PARAM_TYPE_ABC, abc, "A Bee, See?"),
                               PARAM_INST(PARAM_TYPE_DEF, def, "Mos Def"),
                               PARAM_INST(PARAM_TYPE_GHI, ghi, "Gee, Gigli?"),
                               PARAM_INST(PARAM_TYPE_JKL, jkl, "Jeckle, No Hyde"),
                               PARAM_INST_END };

    int   argc = 4;
    char *argv[] = { "abc=42", "def=0xdeadbeef1", "ghi=ben_affleck", "jkl=true" };

    err = process_params(argc, argv, pi, &next_arg, 0);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(abc, 42);
    ASSERT_EQ(def, 0xdeadbeef1);
    ASSERT_EQ(strcmp(ghi, "ben_affleck"), 0);
    ASSERT_EQ(jkl, true);
}

/* 3.1 u8 Test
 */
MTF_DEFINE_UTEST(param, u8_test)
{
    char   value[24];
    u8     list[10];
    u8     a, b;
    merr_t err;

    a = 5;
    err = check_u8(4, 10, &a);
    ASSERT_EQ(err, 0);

    a = 2;
    err = check_u8(4, 10, &a);
    ASSERT_NE(err, 0);

    a = 11;
    err = check_u8(4, 10, &a);
    ASSERT_NE(err, 0);

    err = get_u8(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_u8(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u8("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_u8(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u8(value, 0, &a, 0);
    ASSERT_NE(0, err);

    err = show_u8_dec(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u8_dec(value, 0, &a, 0);
    ASSERT_NE(0, err);

    a = 12;
    sprintf(value, "%u", a);
    err = get_u8(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = 0x12;
    sprintf(value, "%d", a);
    err = get_u8(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = 14;
    err = show_u8(value, sizeof(value), &a, 0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp("0xe", value));

    a = 14;
    err = show_u8_dec(value, sizeof(value), &a, 0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp("14", value));

    err = get_u8_list(value, NULL, 0);
    ASSERT_NE(0, err);

    err = get_u8_list(value, list, 0);
    ASSERT_NE(0, err);

    strcpy(value, "1,,");
    err = get_u8_list(value, list, 10);
    ASSERT_NE(0, err);

    strcpy(value, "1,2,");
    err = get_u8_list(value, list, 10);
    ASSERT_EQ(0, err);
    ASSERT_EQ(list[0], 1);
    ASSERT_EQ(list[1], 2);

    strcpy(value, "x");
    err = get_u8_list(value, list, 10);
    ASSERT_NE(0, err);

    strcpy(value, "1000");
    err = get_u8_list(value, list, 10);
    ASSERT_NE(0, err);

    strcpy(value, "4");
    err = get_u8_list(value, list, 10);
    ASSERT_EQ(0, err);
    ASSERT_EQ(list[0], 4);

    strcpy(value, "4,5,6");
    err = get_u8_list(value, list, 10);
    ASSERT_EQ(0, err);
    ASSERT_EQ(list[0], 4);
    ASSERT_EQ(list[1], 5);
    ASSERT_EQ(list[2], 6);
}

/* 4. u16 Test
 */
MTF_DEFINE_UTEST(param, u16_test)
{
    const u16 av[] = { 0, 1, 2, 3, 4, 2047, 2048, 2049, 4095, 4096, 4097, U16_MAX - 1, U16_MAX };
    char      value[32], buf[32];
    merr_t    err;
    u16       b;
    int       i;

    err = get_u16(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u16(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_u16(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u16("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_u16(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u16(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    err = show_u16(value, 0, &b, 0);
    ASSERT_NE(0, err);

    for (i = 0; i < ARRAY_SIZE(av); ++i) {
        const char * fmtv[] = { "%hu",    "  %hu",      " %hu ",      " \t%hu\t ", "%#hx",
                               "  %#hx", " %#hx ",     " \t%#hx\t ", "%#ho",      "  %#ho",
                               " %#ho ", " \t%#ho\t ", NULL };
        const char **fmt;

        for (fmt = fmtv; *fmt; ++fmt) {
            sprintf(value, *fmt, av[i]);
            err = get_u16(value, &b, sizeof(b));
            ASSERT_EQ(0, err);
            ASSERT_EQ(av[i], b);
        }

        snprintf(buf, sizeof(buf), "0x%hx", av[i]);
        err = show_u16(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));

        snprintf(buf, sizeof(buf), "%hu", av[i]);
        err = show_u16_dec(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));
    }
}

/* 5. u32 Test
 */
MTF_DEFINE_UTEST(param, u32_test)
{
    const u32 av[] = { 0,    1,    2,    3,           4,       2047,        2048,        2049,
                       4095, 4096, 4096, U16_MAX - 1, U16_MAX, U16_MAX + 1, U32_MAX - 1, U32_MAX };
    char      value[32], buf[32];
    merr_t    err;
    u32       b;
    int       i;

    err = get_u32(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u32(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_u32(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u32("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_u32(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u32(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    err = show_u32(value, 0, &b, 0);
    ASSERT_NE(0, err);

    for (i = 0; i < ARRAY_SIZE(av); ++i) {
        const char * fmtv[] = { "%u",    "  %u",  "%u  ",      " %u ",      " \t%u\t ", "%#x",
                               "  %#x", "%#x  ", " %#x ",     " \t%#x\t ", "%#o",      "  %#o",
                               "%#o  ", " %#o ", " \t%#o\t ", NULL };
        const char **fmt;

        for (fmt = fmtv; *fmt; ++fmt) {
            sprintf(value, *fmt, av[i]);
            err = get_u32(value, &b, sizeof(b));
            ASSERT_EQ(0, err);
            ASSERT_EQ(av[i], b);
        }

        snprintf(buf, sizeof(buf), "0x%x", av[i]);
        err = show_u32(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));

        snprintf(buf, sizeof(buf), "%u", av[i]);
        err = show_u32_dec(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));
    }
}

/* 5.05 u32_size Test
 */
MTF_DEFINE_UTEST(param, u32_size_test)
{
    const u32 av[] = { 0,    1,    2,    3,           4,       2047,        2048,        2049,
                       4095, 4096, 4097, U16_MAX - 1, U16_MAX, U16_MAX + 1, U32_MAX - 1, U32_MAX };
    char      value[32];
    merr_t    err;
    u32       b;
    int       i;

    err = get_u32_size(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u32_size(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_u32_size(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u32_size("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_u32_size(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u32_size(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    err = show_u32_size(value, 0, &b, 0);
    ASSERT_NE(0, err);

    for (i = 0; i < ARRAY_SIZE(av); ++i) {
        const char * fmtv[] = { "%u%c",        "  %u%c",       "%u%c  ",       " %u %c ",
                               " \t%u %c\t ", "%#x%c",        "  %#x%c",      "%#x%c  ",
                               " %#x %c ",    " \t%#x %c\t ", "%#o%c",        "  %#o%c",
                               "%#o%c  ",     " %#o %c ",     " \t%#o %c\t ", NULL };
        const char **fmt;

        for (fmt = fmtv; *fmt; ++fmt) {
            const char *sfx = " KkMmGg";
            u32         mult = 1, tmp;

            while (*sfx) {
                if (isupper(*sfx))
                    mult *= 1024;

                tmp = av[i] * mult;
                if (tmp / mult != av[i])
                    break;

                sprintf(value, *fmt, av[i], *sfx);
                err = get_u32_size(value, &b, sizeof(b));
                ASSERT_EQ(0, err);
                ASSERT_EQ(av[i] * mult, b);

                ++sfx;
            }
        }
    }
}

/* 5.1 s32 Test
 */
MTF_DEFINE_UTEST(param, s32_test)
{
    s32    a, b;
    char   value[24];
    merr_t err;

    err = get_s32(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_s32(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_s32(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_s32("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_s32(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_s32(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    err = show_s32(value, 0, &b, 0);
    ASSERT_NE(0, err);

    a = 12;
    sprintf(value, "%d", a);
    err = get_s32(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = 0x12;
    sprintf(value, "%d", a);
    err = get_s32(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = 14;
    err = show_s32(value, sizeof(value), &a, 0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp("0xe", value));
}

/* 6. u64 Test
 */
MTF_DEFINE_UTEST(param, u64_test)
{
    const u64 av[] = { 0,
                       1,
                       2,
                       3,
                       4,
                       2047,
                       2048,
                       2049,
                       4095,
                       4096,
                       4096,
                       U16_MAX - 1,
                       U16_MAX,
                       U16_MAX + 1,
                       U32_MAX - 1,
                       U32_MAX,
                       (u64)U32_MAX + 1,
                       U64_MAX - 1,
                       U64_MAX };
    char      value[32], buf[32];
    merr_t    err;
    u64       b;
    int       i;

    err = get_u64(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u64(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_u64(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u64("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_u64(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u64(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    err = show_u64(value, 0, &b, 0);
    ASSERT_NE(0, err);

    err = show_u64_list(buf, 32, av, 6);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp(buf, "0,1,2,3,4,2047"));

    err = show_u64_list(buf, 1, av, 6);
    ASSERT_EQ(EINVAL, merr_errno(err));

    err = show_u64_list(buf, 8, av, 6);
    ASSERT_EQ(EINVAL, merr_errno(err));

    for (i = 0; i < ARRAY_SIZE(av); ++i) {
        const char * fmtv[] = { "%lu",       "  %lu",      "%lu  ",      " %lu ",
                               " \t%lu\t ", "%#lx",       "  %#lx",     "%#lx  ",
                               " %#lx ",    " \t%#lx\t ", "%#lo",       "  %#lo",
                               "%#lo  ",    " %#lo ",     " \t%#lo\t ", NULL };
        const char **fmt;

        for (fmt = fmtv; *fmt; ++fmt) {
            sprintf(value, *fmt, av[i]);
            err = get_u64(value, &b, sizeof(b));
            ASSERT_EQ(0, err);
            ASSERT_EQ(av[i], b);
        }

        if (av[i] >= 64 * 1024)
            snprintf(buf, sizeof(buf), "0x%lx", av[i]);
        else
            snprintf(buf, sizeof(buf), "%lu", av[i]);
        err = show_u64(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));

        snprintf(buf, sizeof(buf), "%lu", av[i]);
        err = show_u64_dec(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));
    }
}

/* 6.5 u64_size Test
 */
MTF_DEFINE_UTEST(param, u64_size_test)
{
    const u64 av[] = { 0,       1,           2,           3,           4,
                       2047,    2048,        2049,        4095,        4096,
                       4097,    U16_MAX - 1, U16_MAX,     U16_MAX + 1, U32_MAX - 1,
                       U32_MAX, U32_MAX + 1, U64_MAX - 1, U64_MAX };
    char      value[32];
    merr_t    err;
    u64       b;
    int       i;

    err = get_u64_size(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u64_size(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_u64_size(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_u64_size("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_u64_size(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_u64_size(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    err = show_u64_size(value, 0, &b, 0);
    ASSERT_NE(0, err);

    for (i = 0; i < ARRAY_SIZE(av); ++i) {
        const char * fmtv[] = { "%lu%c",        "  %lu%c",       "%lu%c  ",       " %lu %c ",
                               " \t%lu %c\t ", "%#lx%c",        "  %#lx%c",      "%#lx%c  ",
                               " %#lx %c ",    " \t%#lx %c\t ", "%#lo%c",        "  %#lo%c",
                               "%#lo%c  ",     " %#lo %c ",     " \t%#lo %c\t ", NULL };
        const char **fmt;

        for (fmt = fmtv; *fmt; ++fmt) {
            const char *sfx = " KkMmGg";
            u64         mult = 1, tmp;

            while (*sfx) {
                if (isupper(*sfx))
                    mult *= 1024;

                tmp = av[i] * mult;
                if (tmp / mult != av[i])
                    break;

                sprintf(value, *fmt, av[i], *sfx);
                err = get_u64_size(value, &b, sizeof(b));
                ASSERT_EQ(0, err);
                ASSERT_EQ(av[i] * mult, b);

                ++sfx;
            }
        }
    }
}

/* 7. s64 Test
 */
MTF_DEFINE_UTEST(param, s64_test)
{
    const s64 av[] = { S64_MIN,     S64_MIN + 1, S64_MIN + 2, 0,       1,
                       2,           3,           4,           2047,    2048,
                       2049,        4095,        4096,        4096,    S16_MAX - 1,
                       S16_MAX,     S16_MAX + 1, S32_MAX - 1, S32_MAX, (s64)S32_MAX + 1,
                       S64_MAX - 1, S64_MAX };
    char      value[32], buf[32];
    merr_t    err;
    s64       b;
    int       i;

    err = get_s64(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_s64(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = get_s64(value, (char *)&b + 1, sizeof(b));
    ASSERT_NE(0, err);

    err = get_s64("foo", &b, sizeof(b));
    ASSERT_NE(0, err);

    err = show_s64(value, 0, &b, 0);
    ASSERT_NE(0, err);

    err = show_s64(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_s64(value, 0, &b, 0);
    ASSERT_NE(0, err);

    for (i = 0; i < ARRAY_SIZE(av); ++i) {
        const char * fmtv[] = { "%s%ld",       "  %s%ld",      "%s%ld  ",      " %s%ld ",
                               " \t%s%ld\t ", "%s%#lx",       "  %s%#lx",     "%s%#lx  ",
                               " %s%#lx ",    " \t%s%#lx\t ", "%s%#lo",       "  %s%#lo",
                               "%s%#lo  ",    " %s%#lo ",     " \t%s%#lo\t ", NULL };
        const char **fmt;

        for (fmt = fmtv; *fmt; ++fmt) {
            const char *sign = "";
            s64         a = av[i];

            if (av[i] < 0 && fmt > fmtv + 4) {
                sign = "-";
                a = -a;
            }

            sprintf(value, *fmt, sign, a);

            b = ~a;
            err = get_s64(value, &b, sizeof(b));
            ASSERT_EQ(0, err);
            ASSERT_EQ(av[i], b);
        }

        snprintf(buf, sizeof(buf), "0x%lx", av[i]);
        err = show_s64(value, sizeof(value), &av[i], 0);
        ASSERT_EQ(0, err);
        ASSERT_EQ(0, strcmp(buf, value));
    }
}

/* 8. string Test
 */
MTF_DEFINE_UTEST(param, string_test)
{
    char   value[8], val[24];
    merr_t err;

    sprintf(val, "happy");
    err = get_string(value, val, sizeof(val));
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, strcmp(value, val));

    sprintf(val, "sad");
    err = show_string(value, sizeof(value), val, 0);
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, strcmp(value, val));

    strcpy(val, "very very angry");
    err = show_string(value, sizeof(value), val, 0);
    ASSERT_NE(err, 0);
    ASSERT_EQ(0, strncmp(value, val, sizeof(value) - 1));

    strcpy(val, "");
    err = get_string(value, val, sizeof(val));
    ASSERT_EQ(err, 0);
    ASSERT_EQ(0, strcmp(value, val));
}

/* 9. bool Test
 */
MTF_DEFINE_UTEST(param, bool_test)
{
    bool   a, b;
    char   value[24] = { 0 };
    merr_t err;

    err = get_bool(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_bool(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

    err = show_bool(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_bool(value, 0, &b, 0);
    ASSERT_NE(0, err);

    a = true;
    sprintf(value, "true");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = true;
    sprintf(value, "  true \n");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = false;
    sprintf(value, "  trueism");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_NE(0, err);

    a = false;
    sprintf(value, "false");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = false;
    sprintf(value, "\tfalse\t\n");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = false;
    sprintf(value, "falsetto");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_NE(0, err);

    /* Invalid test cases */
    {
        int   i;
        char *invalid[] = {
            "phalse", "0x1", " 0x1", "00x1", "01", "001", "11", "0x0", " 0x0", "00", "2", "",
        };
        for (i = 0; i < NELEM(invalid); i++) {
            err = get_bool(invalid[i], &a, sizeof(a));
            ASSERT_EQ(EINVAL, merr_errno(err));
        }
    }

    a = true;
    sprintf(value, "   1");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = false;
    sprintf(value, "0");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = false;
    sprintf(value, "   0   ");
    err = get_bool(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    b = true;
    err = show_bool(value, sizeof(value), &b, 0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp("true", value));

    b = false;
    err = show_bool(value, sizeof(value), &b, 0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp("false", value));
}

size_t
log_level_set_handler(struct dt_element *dte, struct dt_set_parameters *dsp);

/* 10. log_level Test
 */
MTF_DEFINE_UTEST(param, log_level_test)
{
    log_priority_t a, b;
    char           value[24];
    merr_t         err;

    err = get_log_level(value, NULL, sizeof(b));
    ASSERT_NE(0, err);

    err = get_log_level(value, &b, sizeof(b) - 1);
    ASSERT_NE(0, err);

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
    err = get_log_level(value, (char *)&b - 1, sizeof(b) - 1);
#pragma GCC diagnostic pop
    ASSERT_NE(0, err);

    err = show_log_level(value, sizeof(value), NULL, 0);
    ASSERT_NE(0, err);

    err = show_log_level(value, sizeof(value), (char *)&b + 1, 0);
    ASSERT_NE(0, err);

    a = HSE_INFO_VAL;
    sprintf(value, "HSE_INFO");
    err = get_log_level(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);

    a = HSE_INFO_VAL;
    sprintf(value, "HSE_GOO");
    err = get_log_level(value, &b, sizeof(b));
    ASSERT_EQ(err, 0);
    err = check_u32(HSE_EMERG_VAL, HSE_INVALID_VAL, &b);
    ASSERT_EQ(merr_errno(err), EINVAL);

    a = HSE_ERR_VAL;
    sprintf(value, "3");
    err = get_log_level(value, &b, sizeof(b));
    ASSERT_EQ(0, err);
    ASSERT_EQ(a, b);
    err = check_u32(HSE_EMERG_VAL, HSE_INVALID_VAL, &b);
    ASSERT_EQ(0, err);

    a = HSE_ERR_VAL;
    sprintf(value, "11");
    err = get_log_level(value, &b, sizeof(b));
    ASSERT_EQ(err, 0);
    err = check_u32(HSE_EMERG_VAL, HSE_INVALID_VAL, &b);
    ASSERT_EQ(merr_errno(err), EINVAL);

    a = HSE_CRIT_VAL;
    err = show_log_level(value, sizeof(value), &a, 0);
    ASSERT_EQ(0, err);
    ASSERT_EQ(0, strcmp("HSE_CRIT", value));
}

MTF_END_UTEST_COLLECTION(param)
