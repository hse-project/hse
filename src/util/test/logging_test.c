/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <stdio.h>
#include <stdlib.h>

#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/slab.h>
#include <hse_util/config.h>

#include <hse_ut/framework.h>

#include "../src/logging_impl.h"

#include "mock_log.h"
#include <stddef.h>

#define MAX_NV_PAIRS 50
#define MAX_NV_SIZE 100

#undef hse_xlog
#define hse_xlog(log_fmt, hse_args, ...) hse_log_pri(log_fmt, false, hse_args, ##__VA_ARGS__)

#undef hse_log
#define hse_log(log_fmt, ...) hse_log_pri(log_fmt, false, NULL, ##__VA_ARGS__)

#undef hse_alog
#define hse_alog(log_fmt, ...) hse_log_pri(log_fmt, true, NULL, ##__VA_ARGS__)

void
parse_json_key_values(char *key)
{
    char *curr_pos = NULL;
    int   i = 0, j = 0;
    int   index = 0;
    int   count = 0;

    curr_pos = strstr(shared_result.msg_buffer, key);
    char names[MAX_NV_SIZE];
    char values[MAX_NV_SIZE];

    while (count < 2 && j < MAX_NV_SIZE) {
        if (curr_pos[i] == '"')
            count += 1;

        if (curr_pos[i] != '"' && curr_pos[i] != ':') {
            names[j] = curr_pos[i];
            j++;
        }
        i++;
    }
    names[j] = '\0';
    count = 0;
    j = 0;

    while (count < 2 && j < MAX_NV_SIZE) {

        if (curr_pos[i] == '"')
            count += 1;

        if (count > 1 || curr_pos[i] == '}')
            break;

        if (curr_pos[i] != ',' && curr_pos[i] != '"') {
            values[j] = curr_pos[i];
            j++;
        }
        i++;
    }

    values[j] = '\0';
    index = shared_result.index;

    memcpy(shared_result.names[index], names, sizeof(names));
    memcpy(shared_result.values[index], values, sizeof(values));

    shared_result.index += 1;
    shared_result.count = shared_result.index;
    return;
}

void
process_json_payload(void)
{
    parse_json_key_values("hse_logver");
    parse_json_key_values("hse_version");
    parse_json_key_values("hse_branch");
    parse_json_key_values("hse_0_category");
    parse_json_key_values("hse_0_version");
    parse_json_key_values("hse_0_code");
    parse_json_key_values("hse_0_file");
    parse_json_key_values("hse_0_line");
    parse_json_key_values("hse_0_description");
}

void
process_json_payload_test_string(void)
{
    parse_json_key_values("msg");
}

MTF_BEGIN_UTEST_COLLECTION(hse_logging_test);

MTF_DEFINE_UTEST(hse_logging_test, DoesAnything)
{
    hse_openlog("test", false);

    hse_closelog();
}

MTF_DEFINE_UTEST(hse_logging_test, Test_is_std_specifier)
{
    int i;

    for (i = 0; i < 128; ++i) {
        bool b = is_std_specifier((char)i);

        if (i == 'd' || i == 'i' || i == 'u' || i == 'o' || i == 'x' || i == 'X' || i == 'f' ||
            i == 'F' || i == 'e' || i == 'E' || i == 'g' || i == 'G' || i == 'a' || i == 'A' ||
            i == 'c' || i == 's' || i == 'p' || i == 'n' || i == '%')
            ASSERT_TRUE(b);
        else
            ASSERT_FALSE(b);
    }
}

MTF_DEFINE_UTEST(hse_logging_test, Test_get_std_length_modifier)
{
    enum std_length_modifier m;

    int i;

    static const char *const fa[] = {
        "%d",  "%g", "%hhd", "%hd",  "%d",  "%ld", "%lld", "%jd",    "%zd",     "%td",   "%hhx",
        "%hx", "%x", "%lx",  "%llx", "%jx", "%zx", "%tx",  "%05hhd", "0x016zx", "%7.4Lf"
    };

    enum std_length_modifier ma[] = {
        LEN_MOD_none, LEN_MOD_none, LEN_MOD_hh, LEN_MOD_h,  LEN_MOD_none, LEN_MOD_l,    LEN_MOD_ll,
        LEN_MOD_j,    LEN_MOD_z,    LEN_MOD_t,  LEN_MOD_hh, LEN_MOD_h,    LEN_MOD_none, LEN_MOD_l,
        LEN_MOD_ll,   LEN_MOD_j,    LEN_MOD_z,  LEN_MOD_t,  LEN_MOD_hh,   LEN_MOD_z,    LEN_MOD_L
    };

    int limit = sizeof(fa) / sizeof(const char *);

    for (i = 0; i < limit; ++i) {
        m = get_std_length_modifier((char *)fa[i] + (strlen(fa[i]) - 1));
        ASSERT_EQ(ma[i], m);
    }
}

MTF_DEFINE_UTEST(hse_logging_test, Test_pack_name_value)
{
    char dict_small[20];
    char dict_large[1000];
    bool res;
    int  i;

    struct hse_log_fmt_state state;

    state.num_hse_specs = 1;
    state.hse_spec_cnt = 0;
    state.dict = dict_small;
    state.dict_pos = state.dict;
    state.dict_rem = sizeof(dict_small);

    res = pack_nv(&state, "012", 0, "abc", 0);
    ASSERT_TRUE(res);
    ASSERT_EQ(state.dict + 8, state.dict_pos);
    ASSERT_EQ(sizeof(dict_small) - 8, state.dict_rem);
    ASSERT_EQ('0', state.dict[0]);
    ASSERT_EQ('1', state.dict[1]);
    ASSERT_EQ('2', state.dict[2]);
    ASSERT_EQ(0, state.dict[3]);
    ASSERT_EQ('a', state.dict[4]);
    ASSERT_EQ('b', state.dict[5]);
    ASSERT_EQ('c', state.dict[6]);
    ASSERT_EQ(0, state.dict[7]);
    res = pack_nv(&state, "01", 0, "ab", 0);
    ASSERT_TRUE(res);
    ASSERT_EQ(state.dict + 14, state.dict_pos);
    ASSERT_EQ(sizeof(dict_small) - 14, state.dict_rem);
    ASSERT_EQ('0', state.dict[0]);
    ASSERT_EQ('1', state.dict[1]);
    ASSERT_EQ('2', state.dict[2]);
    ASSERT_EQ(0, state.dict[3]);
    ASSERT_EQ('a', state.dict[4]);
    ASSERT_EQ('b', state.dict[5]);
    ASSERT_EQ('c', state.dict[6]);
    ASSERT_EQ(0, state.dict[7]);
    ASSERT_EQ('0', state.dict[8]);
    ASSERT_EQ('1', state.dict[9]);
    ASSERT_EQ(0, state.dict[3]);
    ASSERT_EQ('a', state.dict[11]);
    ASSERT_EQ('b', state.dict[12]);
    ASSERT_EQ(0, state.dict[13]);

    res = pack_nv(&state, "0", 0, "", 0);
    ASSERT_TRUE(res);
    ASSERT_EQ(state.dict + 17, state.dict_pos);
    ASSERT_EQ(sizeof(dict_small) - 17, state.dict_rem);

    res = pack_nv(&state, "", 0, "", 0);
    ASSERT_TRUE(res);
    ASSERT_EQ(state.dict + 19, state.dict_pos);
    ASSERT_EQ(sizeof(dict_small) - 19, state.dict_rem);

    res = pack_nv(&state, "", 0, "", 0);
    ASSERT_FALSE(res);
    ASSERT_EQ(state.dict + 19, state.dict_pos);

    state.num_hse_specs = 1;
    state.hse_spec_cnt = 0;
    state.dict = dict_large;
    state.dict_pos = state.dict;
    state.dict_rem = sizeof(dict_large);

    for (i = 0; i < 99; ++i) {
        res = pack_nv(&state, "abcd", 0, "1234", 0);
        ASSERT_TRUE(res);
    }

    res = pack_nv(&state, "abcd", 0, "12", 0);
    ASSERT_TRUE(res);

    res = pack_nv(&state, "", 0, "", 0);
    ASSERT_TRUE(res);

    res = pack_nv(&state, "dog", 0, "cat", 0);
    ASSERT_FALSE(res);
}

static bool
_test_fmt(char **pos, char *end, void *obj)
{
    return false;
}

static bool
_test_add(struct hse_log_fmt_state *state, void *obj)
{
    return false;
}

MTF_DEFINE_UTEST(hse_logging_test, Test_string)
{
    const char str[] = "A string with no special characters.";

    hse_openlog("test", true);
    hse_log(HSE_NOTICE "A string with no special characters.");

    ASSERT_TRUE(strstr(shared_result.msg_buffer, str));
    hse_closelog();
}

MTF_DEFINE_UTEST(hse_logging_test, Test_register)
{
    /* basic api: must have ptrs, cannot replace, case sensitive */
    ASSERT_FALSE(hse_log_register('t', 0, 0));
    ASSERT_TRUE(hse_log_register('t', _test_fmt, _test_add));
    ASSERT_FALSE(hse_log_register('t', _test_fmt, _test_add));
    ASSERT_TRUE(hse_log_register('T', _test_fmt, _test_add));

    /* cannot replace builtin -- directly */
    ASSERT_FALSE(hse_log_register('e', _test_fmt, _test_add));

    ASSERT_TRUE(hse_log_deregister('X'));
    ASSERT_FALSE(hse_log_deregister('1'));
    ASSERT_FALSE(hse_log_register('1', _test_fmt, _test_add));

    /* test replacing a formatter */
    ASSERT_FALSE(hse_log_register('T', _test_fmt, _test_add));
    ASSERT_TRUE(hse_log_deregister('T'));
    ASSERT_TRUE(hse_log_register('T', _test_fmt, _test_add));

    /* clean up */
    ASSERT_TRUE(hse_log_deregister('t'));
    ASSERT_TRUE(hse_log_deregister('T'));
}

#if !defined(__HSE_KERNEL_UT__)

MTF_DEFINE_UTEST(hse_logging_test, Test_preprocess_fmt_string_std)
{
    char                     reference[1000], scratch[1000], check[1000];
    char *                   msg = NULL;
    struct hse_log_fmt_state state;
    int                      j = 0;
/*
#if GCC_VERSION > 40500
#pragma GCC diagnostic ignored "-Wformat-zero-length"
#endif
    {
        memset(reference, 0, sizeof(reference));
        memset(scratch,   0, sizeof(scratch));
        memset(check,     0, sizeof(check));

        static const char * const fmt = "";

        state.num_hse_specs = 0;
        state.hse_spec_cnt  = 0;
        state.nv_index = 0;
        state.nv_hse_index = 0;

        sprintf(reference, fmt);

        test_preprocess_fmt_string(
            &state,
            fmt,
            scratch,
            sizeof(scratch),
            0
        );
        ASSERT_STREQ(reference, scratch);

    }
#if GCC_VERSION > 40500
#pragma GCC diagnostic warning "-Wformat-zero-length"
#endif
    {
        memset(reference, 0, sizeof(reference));
        memset(scratch,   0, sizeof(scratch));
        memset(check,     0, sizeof(check));

        static const char * const fmt = "some constant string ...";

        state.num_hse_specs = 0;
        state.hse_spec_cnt  = 0;
        state.nv_index = 0;
        state.nv_hse_index = 0;

        sprintf(reference, fmt);

        test_preprocess_fmt_string(
            &state,
            fmt,
            scratch,
            sizeof(scratch),
            0
        );


        ASSERT_STREQ(reference, scratch);
    }
*/
#if GCC_VERSION > 40500
#pragma GCC diagnostic warning "-Wformat-zero-length"
#endif
    {
        memset(reference, 0, sizeof(reference));
        memset(scratch, 0, sizeof(scratch));
        memset(check, 0, sizeof(check));

        int                      i = 42;
        static const char *const fmt = "A simple string with an int (%d) in it.";

        state.num_hse_specs = 0;
        state.hse_spec_cnt = 0;
        state.nv_index = 0;
        state.nv_hse_index = 0;

        sprintf(reference, fmt, i);

        test_finalize_log_structure(
            &state, false, __FILE__, 1, fmt, scratch, sizeof(scratch), 0, i);
        msg = strstr(shared_result.msg_buffer, reference);

        while (msg[j] != '"') {
            check[j] = msg[j];
            j++;
        }

        check[j] = '\0';

        ASSERT_STREQ(reference, check);
    }

    {
        memset(reference, 0, sizeof(reference));
        memset(scratch, 0, sizeof(scratch));
        memset(check, 0, sizeof(check));

        static const char *const fmt = "Prefix %hhd infix %hd infix %ld - %g.";

        char  c = 17;
        short s = 31783;
        long  l = 2893718;
        float g = 3.14159265;

        state.num_hse_specs = 0;
        state.hse_spec_cnt = 0;
        state.nv_index = 0;
        state.nv_hse_index = 0;

        sprintf(reference, fmt, c, s, l, g);

        test_finalize_log_structure(
            &state, false, __FILE__, 1, fmt, scratch, sizeof(scratch), 0, c, s, l, g);

        msg = strstr(shared_result.msg_buffer, reference);

        j = 0;
        while (msg[j] != '"') {
            check[j] = msg[j];
            j++;
        }

        check[j] = '\0';

        ASSERT_STREQ(reference, check);
    }

    {
        memset(reference, 0, sizeof(reference));
        memset(scratch, 0, sizeof(scratch));
        memset(check, 0, sizeof(check));

        static const char *const fmt = "Prefix 0x%016lx - %lu";
        int                      c;
        ptrdiff_t                d;

        d = ((unsigned long)&fmt) - ((unsigned long)&c);

        state.num_hse_specs = 0;
        state.hse_spec_cnt = 0;
        state.nv_index = 0;
        state.nv_hse_index = 0;

        sprintf(reference, fmt, (unsigned long)&fmt, d);

        test_finalize_log_structure(
            &state, false, __FILE__, 1, fmt, scratch, sizeof(scratch), 0, &fmt, d);

        msg = strstr(shared_result.msg_buffer, reference);

        j = 0;
        while (msg[j] != '"') {
            check[j] = msg[j];
            j++;
        }

        check[j] = '\0';

        ASSERT_STREQ(reference, check);
    }
}

#endif /* !defined(__HSE_KERNEL_UT__) */

MTF_DEFINE_UTEST(hse_logging_test, Test_log_call)
{
    merr_t err;
    void * av[] = { &err, 0 };

    char code_as_string[12];
    char line_as_string[12];
    char description[300];
    int  ix = 0;

    err = merr(ENOMEM);

    snprintf(code_as_string, sizeof(code_as_string), "%d", merr_errno(err));
    snprintf(line_as_string, sizeof(line_as_string), "%d", merr_lineno(err));

    merr_strerror(err, description, sizeof(description));

    hse_xlog(
        HSE_ERR "[UNIT TEST] Error in strdup() while modifying "
                "configuration: @@e",
        av);

    process_json_payload();

    ASSERT_EQ(9, shared_result.count);

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_branch", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_0_category", shared_result.names[ix]);
    ASSERT_STREQ("hse_error", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_version", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_code", shared_result.names[ix]);
    ASSERT_STREQ(code_as_string, shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_file", shared_result.names[ix]);
    ASSERT_STREQ("test/logging_test.c", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_line", shared_result.names[ix]);
    ASSERT_STREQ(line_as_string, shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_description", shared_result.names[ix]);
    ASSERT_STREQ(description, shared_result.values[ix]);
    ix++;

    ASSERT_EQ(ix, shared_result.count);
}

MTF_DEFINE_UTEST(hse_logging_test, Test_set_pri_and_verbose)
{
    hse_openlog("test", false);
    ASSERT_EQ(HSE_LOG_PRI_DEFAULT, hse_logging_control.mlc_cur_pri);
    ASSERT_EQ(false, hse_logging_control.mlc_verbose);
    ASSERT_NE(HSE_WARNING_VAL, HSE_LOG_PRI_DEFAULT);

    hse_log_set_pri(HSE_WARNING_VAL);
    ASSERT_EQ(HSE_WARNING_VAL, hse_logging_control.mlc_cur_pri);

    hse_log_set_verbose(true);
    ASSERT_EQ(true, hse_logging_control.mlc_verbose);

    hse_closelog();
}

MTF_DEFINE_UTEST(hse_logging_test, Test_hse_logprio_val_to_name)
{
    const char *name;

    name = hse_logprio_val_to_name(HSE_DEBUG_VAL);
    ASSERT_EQ(0, strncmp("HSE_DEBUG", name, strlen("HSE_DEBUG")));

    name = hse_logprio_val_to_name(HSE_INFO_VAL);
    ASSERT_EQ(0, strncmp("HSE_INFO", name, strlen("HSE_INFO")));

    name = hse_logprio_val_to_name(HSE_NOTICE_VAL);
    ASSERT_EQ(0, strncmp("HSE_NOTICE", name, strlen("HSE_NOTICE")));

    name = hse_logprio_val_to_name(HSE_WARNING_VAL);
    ASSERT_EQ(0, strncmp("HSE_WARNING", name, strlen("HSE_WARNING")));

    name = hse_logprio_val_to_name(HSE_ERR_VAL);
    ASSERT_EQ(0, strncmp("HSE_ERR", name, strlen("HSE_ERR")));

    name = hse_logprio_val_to_name(HSE_CRIT_VAL);
    ASSERT_EQ(0, strncmp("HSE_CRIT", name, strlen("HSE_CRIT")));

    name = hse_logprio_val_to_name(HSE_ALERT_VAL);
    ASSERT_EQ(0, strncmp("HSE_ALERT", name, strlen("HSE_ALERT")));

    name = hse_logprio_val_to_name(HSE_EMERG_VAL);
    ASSERT_EQ(0, strncmp("HSE_EMERG", name, strlen("HSE_EMERG")));
}

MTF_DEFINE_UTEST(hse_logging_test, Test_hse_logprio_name_to_val)
{
    log_priority_t pri;

    pri = hse_logprio_name_to_val("HSE_DEBUG");
    ASSERT_EQ(pri, HSE_DEBUG_VAL);

    pri = hse_logprio_name_to_val("HSE_INFO");
    ASSERT_EQ(pri, HSE_INFO_VAL);

    pri = hse_logprio_name_to_val("HSE_NOTICE");
    ASSERT_EQ(pri, HSE_NOTICE_VAL);

    pri = hse_logprio_name_to_val("HSE_WARNING");
    ASSERT_EQ(pri, HSE_WARNING_VAL);

    pri = hse_logprio_name_to_val("hse_warning");
    ASSERT_EQ(pri, HSE_WARNING_VAL);

    pri = hse_logprio_name_to_val("WARNING");
    ASSERT_EQ(pri, HSE_WARNING_VAL);

    pri = hse_logprio_name_to_val("warning");
    ASSERT_EQ(pri, HSE_WARNING_VAL);

    pri = hse_logprio_name_to_val("WARN");
    ASSERT_EQ(pri, HSE_WARNING_VAL);

    pri = hse_logprio_name_to_val("warn");
    ASSERT_EQ(pri, HSE_WARNING_VAL);

    pri = hse_logprio_name_to_val("HSE_ERR");
    ASSERT_EQ(pri, HSE_ERR_VAL);

    pri = hse_logprio_name_to_val("HSE_CRIT");
    ASSERT_EQ(pri, HSE_CRIT_VAL);

    pri = hse_logprio_name_to_val("HSE_ALERT");
    ASSERT_EQ(pri, HSE_ALERT_VAL);

    pri = hse_logprio_name_to_val("HSE_EMERG");
    ASSERT_EQ(pri, HSE_EMERG_VAL);
}

MTF_DEFINE_UTEST(hse_logging_test, Test_hse_alog)
{
    merr_t rc;
    int    i;

    hse_logging_fini();
    rc = hse_logging_init();
    ASSERT_EQ(0, rc);
    hse_log_set_verbose(true);

    hse_log(HSE_ERR "Test %s %d", "test", -1);

    /*
     * Fill up the circular buffer and overflow it by 20 entries
     * before the consumer thread has a chance to start filling it.
     * Only the first MAX_LOGGING_ASYNC_ENTRIES should show, the last 20
     * shoud be discarded.
     */
    for (i = 0; i < MAX_LOGGING_ASYNC_ENTRIES + 20; i++)
        hse_alog(HSE_ERR "Test %s %d", "test", i);
    /*
     * Give the consumer thread time  to consume and show all
     * MAX_LOGGING_ASYNC_ENTRIES log messages.
     */
    sleep(2);

    /* Post 10 new messages, these ones shpuld show and not be discarded. */
    for (i = 0; i < 10; i++)
        hse_alog(HSE_ERR "Test %s %d", "test after overflow", i);

    hse_logging_fini();
}

MTF_DEFINE_UTEST(hse_logging_test, Test_hse_slog)
{
    int   argc = 3;
    char *argv[3] = { "abc", "123", "!@#" };

    hse_logging_fini();
    hse_logging_init();

    /* [HSE_REVISIT]
     * Should be able to use shared_result to assert the output.
     * These message are currently logged in journalctl.
     */

    hse_slog(
        HSE_NOTICE,
        HSE_SLOG_START("utest"),
        HSE_SLOG_FIELD("desc", "%s", "object with field"),
        HSE_SLOG_FIELD("hello", "%s", "world"),
        HSE_SLOG_END);

    hse_slog(
        HSE_NOTICE,
        HSE_SLOG_START("utest"),
        HSE_SLOG_FIELD("desc", "%s", "object with list"),
        HSE_SLOG_LIST("content", "%s", argc, argv),
        HSE_SLOG_END);

    hse_slog(
        HSE_NOTICE,
        HSE_SLOG_START("utest"),
        HSE_SLOG_FIELD("desc", "%s", "nested object"),
        HSE_SLOG_CHILD_START("level_1"),
        HSE_SLOG_CHILD_START("level_2"),
        HSE_SLOG_FIELD("foobar", "%d", 2000),
        HSE_SLOG_CHILD_END,
        HSE_SLOG_CHILD_END,
        HSE_SLOG_END);

    hse_slog(
        HSE_NOTICE,
        HSE_SLOG_START("foobar"),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_0", "%u", 0),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_1", "%u", 1),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_2", "%u", 2),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_3", "%u", 3),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_4", "%u", 4),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_5", "%u", 5),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_6", "%u", 6),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_7", "%u", 7),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_8", "%u", 8),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_9", "%u", 9),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_10", "%u", 10),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_11", "%u", 11),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_12", "%u", 12),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_13", "%u", 13),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_14", "%u", 14),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_15", "%u", 15),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_16", "%u", 16),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_17", "%u", 17),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_18", "%u", 18),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_19", "%u", 19),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_20", "%u", 20),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_21", "%u", 21),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_22", "%u", 22),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_23", "%u", 23),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_24", "%u", 24),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_25", "%u", 25),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_26", "%u", 26),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_27", "%u", 27),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_28", "%u", 28),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_29", "%u", 29),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_30", "%u", 30),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_31", "%u", 31),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_32", "%u", 32),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_33", "%u", 33),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_34", "%u", 34),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_35", "%u", 35),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_36", "%u", 36),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_37", "%u", 37),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_38", "%u", 38),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_39", "%u", 39),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_40", "%u", 40),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_41", "%u", 41),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_42", "%u", 42),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_43", "%u", 43),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_44", "%u", 44),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_45", "%u", 45),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_46", "%u", 46),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_47", "%u", 47),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_48", "%u", 48),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_49", "%u", 49),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_50", "%u", 50),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_51", "%u", 51),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_52", "%u", 52),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_53", "%u", 53),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_54", "%u", 54),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_55", "%u", 55),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_56", "%u", 56),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_57", "%u", 57),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_58", "%u", 58),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_59", "%u", 59),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_60", "%u", 60),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_61", "%u", 61),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_62", "%u", 62),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_63", "%u", 63),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_64", "%u", 64),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_65", "%u", 65),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_66", "%u", 66),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_67", "%u", 67),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_68", "%u", 68),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_69", "%u", 69),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_70", "%u", 70),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_71", "%u", 71),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_72", "%u", 72),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_73", "%u", 73),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_74", "%u", 74),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_75", "%u", 75),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_76", "%u", 76),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_77", "%u", 77),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_78", "%u", 78),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_79", "%u", 79),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_80", "%u", 80),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_81", "%u", 81),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_82", "%u", 82),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_83", "%u", 83),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_84", "%u", 84),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_85", "%u", 85),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_86", "%u", 86),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_87", "%u", 87),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_88", "%u", 88),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_89", "%u", 89),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_90", "%u", 90),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_91", "%u", 91),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_92", "%u", 92),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_93", "%u", 93),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_94", "%u", 94),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_95", "%u", 95),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_96", "%u", 96),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_97", "%u", 97),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_98", "%u", 98),
        HSE_SLOG_FIELD("xxxxxxxxxxxxxxxxxxxxxxxx_99", "%u", 99),
        HSE_SLOG_END);

    hse_logging_fini();
}

MTF_DEFINE_UTEST(hse_logging_test, Test_hse_slog_dynamic)
{
    int                  i;
    struct slog *        logger;
    struct json_context *jc;

    struct kv_pair {
        char *key;
        int   val;
    };

    struct kv_pair kv_table[] = { { "answer", 42 }, { "foobar", 2000 } };

    hse_logging_fini();
    hse_logging_init();

    hse_slog_create(HSE_NOTICE, &logger, "utest");

    jc = &logger->sl_json;

    hse_slog_append(logger, HSE_SLOG_FIELD("desc", "%s", "dynamic log"));
    for (i = 0; i < 2; i++) {
        char *key = kv_table[i].key;
        int   val = kv_table[i].val;

        hse_slog_append(logger, HSE_SLOG_FIELD(key, "%d", val));
    }

    /* check for source info */
    ASSERT_NE(strstr(jc->json_buf, "hse_logver"), NULL);
    ASSERT_NE(strstr(jc->json_buf, "hse_version"), NULL);
    ASSERT_NE(strstr(jc->json_buf, "hse_branch"), NULL);

    /* check for keys */
    ASSERT_NE(strstr(jc->json_buf, "\"type\":\"utest\""), NULL);
    ASSERT_NE(strstr(jc->json_buf, "\"desc\":\"dynamic log\""), NULL);
    ASSERT_NE(strstr(jc->json_buf, "\"answer\":42"), NULL);
    ASSERT_NE(strstr(jc->json_buf, "\"foobar\":2000"), NULL);

    hse_slog_commit(logger);

    hse_logging_fini();
}

MTF_DEFINE_UTEST(hse_logging_test, Test_hse_slog_dynamic_resize)
{
    int                  i, original;
    struct slog *        logger;
    struct json_context *jc;

    hse_logging_fini();
    hse_logging_init();

    hse_slog_create(HSE_NOTICE, &logger, "utest");

    jc = &logger->sl_json;
    original = jc->json_buf_sz;

    hse_slog_append(logger, HSE_SLOG_FIELD("desc", "%s", "resize dynamic log"));

    for (i = 0; i < 128; i++)
        hse_slog_append(logger, HSE_SLOG_FIELD("x", "%d", i));

    ASSERT_EQ(original * 2, jc->json_buf_sz);

    hse_slog_commit(logger);

    hse_logging_fini();
}

MTF_END_UTEST_COLLECTION(hse_logging_test);
