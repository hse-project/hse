/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/hse_err.h>
#include <hse_util/parser.h>

#include "../src/parser_internal.h"

#include <hse_ut/framework.h>
#include <hse_test_support/allocation.h>

MTF_MODULE_UNDER_TEST(hse_platform);

MTF_BEGIN_UTEST_COLLECTION(parser_test);

MTF_DEFINE_UTEST(parser_test, arg_checking)
{
    int         rv;
    char *      p;
    char *      str_src = "heeminyjeeminy";
    substring_t val;
    int         result;
    char *      num_src = "42";
    char        buffer[100];

    match_table_t empty_options = { { 0, 0 } };
    match_table_t options = {
        { 0, "zero" }, { -1, NULL },
    };

    rv = match_token(0, empty_options, &val);
    ASSERT_EQ(rv, 0);
    rv = match_token(str_src, empty_options, 0);
    ASSERT_EQ(rv, 0);

    rv = match_token(0, options, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token(str_src, options, 0);
    ASSERT_EQ(rv, -1);

    val.from = num_src;
    val.to = num_src + strlen(num_src);

    rv = match_number(0, &result, 0);
    ASSERT_EQ(rv, -EINVAL);
    rv = match_number(&val, 0, 0);
    ASSERT_EQ(rv, -EINVAL);

    val.from = str_src;
    val.to = str_src + strlen(str_src);

    memset(buffer, 0, sizeof(buffer));
    rv = match_strlcpy(0, &val, sizeof(buffer));
    ASSERT_EQ(rv, 0);
    rv = match_strlcpy(buffer, 0, sizeof(buffer));
    ASSERT_EQ(rv, 0);

    p = match_strdup(0);
    ASSERT_EQ(p, NULL);
}

MTF_DEFINE_UTEST(parser_test, match_once_test)
{
    u32         mtchd;
    u32         val_fnd;
    substring_t val;
    int         i;

    char *empty_str = "";
    char *empty_ptrn = "";
    char *ptrn1 = "verbose";
    char *ptrn2 = "bob=%s";
    char *ptrn3 = "bob=%t";
    char *str1 = "bob";
    char *str2 = "bob%%";
    char *str3 = "bob=";
    char *match_with_pct1 = "BobDobbs%%%%";
    char *match_with_pct2 = "BobDobbs%%%%%";
    char *match_with_pct3 = "BobDobbs%%X";
    char *match_with_pct4 = "BobDobbs%%%";
    char *with_eq[] = { "=", "bob=", "=bob", "cat=ob", "1=23=" };
    char *with_pct[] = { "%", "bob=%", "=bob%%" };
    char *strN;
    char *ptrnN;
    char  buffer[1000];
    s64   s_val;
    u64   u_val;

    /* empty string & empty pattern */
    mtchd = val_fnd = 0;
    match_once(empty_str, empty_ptrn, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 0);

    /* non-empty string & empty pattern */
    mtchd = val_fnd = 0;
    match_once(str1, empty_ptrn, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* empty string & non-empty pattern */
    mtchd = val_fnd = 0;
    match_once(empty_str, ptrn1, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* string with '=', pattern with no conversion specifiers */
    for (i = 0; i < sizeof(with_eq) / sizeof(char *); ++i) {
        mtchd = val_fnd = 0;
        match_once(with_eq[i], ptrn1, &mtchd, &val_fnd, &val);
        ASSERT_EQ(mtchd, 0);
        ASSERT_EQ(val_fnd, 0);
    }

    /* pattern with '=' and no conversion specifiers */
    for (i = 0; i < sizeof(with_eq) / sizeof(char *); ++i) {
        mtchd = val_fnd = 0;
        match_once(str1, with_eq[i], &mtchd, &val_fnd, &val);
        ASSERT_EQ(mtchd, 0);
        ASSERT_EQ(val_fnd, 0);
    }

    /* matching string and pattern */
    mtchd = val_fnd = 0;
    match_once(ptrn1, ptrn1, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 0);

    /* matching string and pattern with % */
    mtchd = val_fnd = 0;
    match_once(match_with_pct1, match_with_pct1, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 0);

    /* non-matching string and pattern with % */
    mtchd = val_fnd = 0;
    match_once(match_with_pct1, match_with_pct2, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);
    mtchd = val_fnd = 0;
    match_once(match_with_pct2, match_with_pct1, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);
    mtchd = val_fnd = 0;
    match_once(match_with_pct3, match_with_pct4, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);
    mtchd = val_fnd = 0;
    match_once(match_with_pct4, match_with_pct3, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* matching string, pattern with %s, empty value */
    mtchd = val_fnd = 0;
    match_once(str3, ptrn2, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    ASSERT_EQ(val.to - val.from, 0);

    /* matching prefix string, invalid pattern with %t */
    mtchd = val_fnd = 0;
    match_once(str3, ptrn3, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* patterns with '%' but no conversion specifiers */
    for (i = 0; i < sizeof(with_pct) / sizeof(char *); ++i) {
        mtchd = val_fnd = 0;
        match_once(str1, with_eq[i], &mtchd, &val_fnd, &val);
        ASSERT_EQ(mtchd, 0);
        ASSERT_EQ(val_fnd, 0);
        mtchd = val_fnd = 0;
        match_once(str2, with_eq[i], &mtchd, &val_fnd, &val);
        ASSERT_EQ(mtchd, 0);
        ASSERT_EQ(val_fnd, 0);
    }

    /* matches with '=' characters */
    for (i = 0; i < sizeof(with_eq) / sizeof(char *); ++i) {
        mtchd = val_fnd = 0;
        match_once(with_eq[i], with_eq[i], &mtchd, &val_fnd, &val);
        ASSERT_EQ(mtchd, 1);
        ASSERT_EQ(val_fnd, 0);
    }

    /* matches with '%' characters */
    for (i = 0; i < sizeof(with_pct) / sizeof(char *); ++i) {
        mtchd = val_fnd = 0;
        match_once(with_pct[i], with_pct[i], &mtchd, &val_fnd, &val);
        ASSERT_EQ(mtchd, 1);
        ASSERT_EQ(val_fnd, 0);
    }

    /* string conversion specifier, simple match */
    strN = "verbose=true";
    ptrnN = "verbose=%s";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    snprintf(buffer, val.to - val.from + 1, "%s", val.from);
    ASSERT_EQ(strcmp("true", buffer), 0);

    /* string conversion specifier, no match */
    strN = "verbose=true";
    ptrnN = "verbos=%s";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* string conversion specifier, match with truncated value */
    strN = "verbose=true";
    ptrnN = "verbose=%2s";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    snprintf(buffer, val.to - val.from + 1, "%s", val.from);
    ASSERT_EQ(strcmp("tr", buffer), 0);

    /* string conversion specifier, match with value shorter than limit */
    strN = "verbose=true";
    ptrnN = "verbose=%10s";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    snprintf(buffer, val.to - val.from + 1, "%s", val.from);
    ASSERT_EQ(strcmp("true", buffer), 0);

    /* integer conversion specifier (d), no match */
    strN = "verbose=1";
    ptrnN = "verbos=%d";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* integer conversion specifier (d), simple match in decimal */
    strN = "level=-17";
    ptrnN = "level=%d";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    s_val = strtol(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(s_val, -17);

    /* integer conversion specifier (d), simple match in hex */
    strN = "level=0x10";
    ptrnN = "level=%d";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    s_val = strtol(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(s_val, 16);

    /* integer conversion specifier (d), simple match in octal */
    strN = "level=020";
    ptrnN = "level=%d";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    s_val = strtol(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(s_val, 16);

    /* integer conversion specifier (u), no match */
    strN = "bose=1";
    ptrnN = "bos=%u";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* integer conversion specifier (u), simple match in decimal */
    strN = "level=17";
    ptrnN = "level=%u";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    u_val = strtoul(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(u_val, 17);

    /* integer conversion specifier (u), simple match w/ negative value */
    strN = "level=-17";
    ptrnN = "level=%u";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    u_val = strtoul(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(u_val, (unsigned long)-17);

    /* integer conversion specifier (u), simple match in hex */
    strN = "level=0x10";
    ptrnN = "level=%u";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    u_val = strtoul(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(u_val, 16);

    /* integer conversion specifier (u), simple match in octal */
    strN = "level=020";
    ptrnN = "level=%u";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    u_val = strtoul(val.from, 0, 0);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(u_val, 16);

    /* integer conversion specifier (o), simple match in octal */
    strN = "level=30";
    ptrnN = "level=%o";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    u_val = strtoul(val.from, 0, 8);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(u_val, 24);

    /* integer conversion specifier (o), simple match, bad value */
    strN = "level=9";
    ptrnN = "level=%o";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* integer conversion specifier (x), simple match in hex */
    strN = "level=a0";
    ptrnN = "level=%x";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 1);
    ASSERT_EQ(val_fnd, 1);
    errno = 0;
    u_val = strtoul(val.from, 0, 16);
    ASSERT_EQ(errno, 0);
    ASSERT_EQ(u_val, 160);

    /* integer conversion specifier (o), simple match, bad value */
    strN = "level=9";
    ptrnN = "level=%o";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);

    /* integer conversion specifier (d), simple match, bad value */
    strN = "level=18446744073709551615123";
    ptrnN = "level=%d";
    mtchd = val_fnd = 0;
    match_once(strN, ptrnN, &mtchd, &val_fnd, &val);
    ASSERT_EQ(mtchd, 0);
    ASSERT_EQ(val_fnd, 0);
}

MTF_DEFINE_UTEST(parser_test, match_token_test)
{
    int         rv;
    substring_t val;
    char        buffer[1000];
    s64         s_val;
    u64         u_val;

    match_table_t empty_options = { { 0, 0 } };
    match_table_t options1 = { { 1, "robert=%s" }, { -1, 0 } };
    match_table_t options2 = { { 1, "" },         { 2, "steve" },      { 3, "susan=%s" },
                               { 4, "larry=%d" }, { 5, "lucille=%o" }, { 6, "desi=%u" },
                               { 7, "" },         { 8, "jane=%x" },    { 10, "robert=%s" },
                               { -1, 0 } };

    rv = match_token("", empty_options, &val);
    ASSERT_EQ(rv, 0);
    rv = match_token("verbose=1", empty_options, &val);
    ASSERT_EQ(rv, 0);

    rv = match_token("verbose=1", options1, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("robert=1", options1, &val);
    ASSERT_EQ(rv, 1);
    snprintf(buffer, val.to - val.from + 1, "%s", val.from);
    ASSERT_EQ(strcmp("1", buffer), 0);

    rv = match_token("susan", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("larry", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("larry=cat", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("lucille", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("lucille=doh", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("desi", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("desi=!", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("jane", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("jane=", options2, &val);
    ASSERT_EQ(rv, -1);
    rv = match_token("robert", options2, &val);
    ASSERT_EQ(rv, -1);

    rv = match_token("steve", options2, &val);
    ASSERT_EQ(rv, 2);
    rv = match_token("susan=aunt", options2, &val);
    ASSERT_EQ(rv, 3);
    rv = match_token("larry=-12", options2, &val);
    ASSERT_EQ(rv, 4);
    s_val = strtol(val.from, 0, 0);
    ASSERT_EQ(s_val, -12);
    rv = match_token("lucille=-17", options2, &val);
    ASSERT_EQ(rv, 5);
    s_val = strtol(val.from, 0, 8);
    ASSERT_EQ(s_val, -15);
    rv = match_token("desi=129803", options2, &val);
    ASSERT_EQ(rv, 6);
    u_val = strtol(val.from, 0, 0);
    ASSERT_EQ(u_val, 129803);
    rv = match_token("jane=e", options2, &val);
    ASSERT_EQ(rv, 8);
    s_val = strtol(val.from, 0, 16);
    ASSERT_EQ(s_val, 14);
}

MTF_DEFINE_UTEST(parser_test, match_number_test)
{
    int         rv;
    int         result;
    substring_t substr;
    char *      source = "42";
    char *      pos_dec = "2948";
    char *      neg_dec = "-91";
    char *      pos_oct = "71";
    char *      neg_oct = "-71";
    char *      pos_hex = "a1";
    char *      neg_hex = "-a1";
    char *      not_hex = "123g";
    char *      too_big = "3000000000";
    char *      too_small = "-3000000000";
    char *      way_too_big = "18446744073709551615123";

    substr.from = source;
    substr.to = source + strlen(source);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    mapi_inject_once_ptr(mapi_idx_free, 1, NULL);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, -ENOMEM);
    ASSERT_EQ(1, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(0, mapi_calls(mapi_idx_free));
    mapi_inject_clear();

    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 42);
    ASSERT_EQ(1, mapi_calls(mapi_idx_malloc));
    ASSERT_EQ(1, mapi_calls(mapi_idx_free));

    substr.from = pos_dec;
    substr.to = pos_dec + strlen(pos_dec);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 2948);
    rv = match_number(&substr, &result, 10);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 2948);

    substr.from = neg_dec;
    substr.to = neg_dec + strlen(neg_dec);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -91);
    rv = match_number(&substr, &result, 10);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -91);

    substr.from = pos_oct;
    substr.to = pos_oct + strlen(pos_oct);
    rv = match_number(&substr, &result, 8);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 57);

    substr.from = neg_oct;
    substr.to = neg_oct + strlen(neg_oct);
    rv = match_number(&substr, &result, 8);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -57);

    substr.from = pos_hex;
    substr.to = pos_hex + strlen(pos_hex);
    rv = match_number(&substr, &result, 16);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 161);

    substr.from = neg_hex;
    substr.to = neg_hex + strlen(neg_hex);
    rv = match_number(&substr, &result, 16);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -161);

    /* Count subsequent calls to malloc/free */
    mapi_inject_clear();

    substr.from = pos_hex;
    substr.to = pos_hex + strlen(pos_hex);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, -EINVAL);

    substr.from = pos_dec;
    substr.to = pos_dec + strlen(pos_dec);
    rv = match_number(&substr, &result, 8);
    ASSERT_EQ(rv, -EINVAL);

    substr.from = not_hex;
    substr.to = not_hex + strlen(not_hex);
    rv = match_number(&substr, &result, 16);
    ASSERT_EQ(rv, -EINVAL);

    substr.from = too_big;
    substr.to = too_big + strlen(too_big);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, -ERANGE);

    substr.from = too_big;
    substr.to = too_big + strlen(too_big);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, -ERANGE);

    substr.from = too_small;
    substr.to = too_small + strlen(too_small);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, -ERANGE);

    substr.from = way_too_big;
    substr.to = way_too_big + strlen(way_too_big);
    rv = match_number(&substr, &result, 0);
    ASSERT_EQ(rv, -EINVAL);

    ASSERT_GE(mapi_calls(mapi_idx_malloc), 7);
    ASSERT_EQ(mapi_calls(mapi_idx_malloc), mapi_calls(mapi_idx_free));

    mapi_inject_clear();
}

MTF_DEFINE_UTEST(parser_test, match_int_octal_hex_test)
{
    int         rv;
    int         result;
    substring_t substr;
    char *      pos_dec = "2948";
    char *      neg_dec = "-91";
    char *      pos_oct = "71";
    char *      neg_oct = "-71";
    char *      pos_hex = "a1";
    char *      neg_hex = "-a1";
    char *      not_hex = "123g";

    substr.from = pos_dec;
    substr.to = pos_dec + strlen(pos_dec);
    rv = match_int(&substr, &result);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 2948);
    rv = match_octal(&substr, &result);
    ASSERT_EQ(rv, -EINVAL);

    substr.from = neg_dec;
    substr.to = neg_dec + strlen(neg_dec);
    rv = match_int(&substr, &result);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -91);
    rv = match_octal(&substr, &result);
    ASSERT_EQ(rv, -EINVAL);

    substr.from = pos_oct;
    substr.to = pos_oct + strlen(pos_oct);
    rv = match_octal(&substr, &result);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 57);

    substr.from = neg_oct;
    substr.to = neg_oct + strlen(neg_oct);
    rv = match_octal(&substr, &result);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -57);

    substr.from = pos_hex;
    substr.to = pos_hex + strlen(pos_hex);
    rv = match_hex(&substr, &result);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, 161);

    substr.from = neg_hex;
    substr.to = neg_hex + strlen(neg_hex);
    rv = match_hex(&substr, &result);
    ASSERT_EQ(rv, 0);
    ASSERT_EQ(result, -161);

    substr.from = not_hex;
    substr.to = not_hex + strlen(not_hex);
    rv = match_hex(&substr, &result);
    ASSERT_EQ(rv, -EINVAL);
}

MTF_DEFINE_UTEST(parser_test, match_copy_dup_test)
{
    int         rv;
    substring_t substr;
    char *      source = "heeminyjeeminy";
    char *      p;
    char        buffer[1000];
    int         source_len;

    source_len = strlen(source);
    substr.from = source;
    substr.to = source + source_len;

    memset(buffer, 0, sizeof(buffer));
    rv = match_strlcpy(buffer, &substr, sizeof(buffer));
    ASSERT_EQ(rv, source_len);
    ASSERT_EQ(0, strcmp(source, buffer));

    memset(buffer, 0, sizeof(buffer));
    rv = match_strlcpy(buffer, &substr, 0);
    ASSERT_EQ(rv, source_len);
    ASSERT_EQ(buffer[0], 0);

    memset(buffer, 0, sizeof(buffer));
    rv = match_strlcpy(buffer, &substr, 1);
    ASSERT_EQ(rv, source_len);
    ASSERT_EQ(buffer[0], 0);

    memset(buffer, 0, sizeof(buffer));
    rv = match_strlcpy(buffer, &substr, 2);
    ASSERT_EQ(rv, source_len);
    ASSERT_EQ(buffer[0], 'h');
    ASSERT_EQ(buffer[1], 0);

    mapi_inject_once_ptr(mapi_idx_malloc, 1, NULL);
    mapi_inject_once_ptr(mapi_idx_free, 1, NULL);
    p = match_strdup(&substr);
    ASSERT_EQ(p, NULL);

    p = match_strdup(&substr);
    ASSERT_NE(p, NULL);
    ASSERT_EQ(strcmp(p, source), 0);
    ASSERT_EQ(mapi_calls(mapi_idx_malloc), 2);
    ASSERT_EQ(mapi_calls(mapi_idx_free), 0);
    free(p);
}

MTF_END_UTEST_COLLECTION(parser_test)
