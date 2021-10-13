/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/config.h>
#include <hse_util/data_tree.h>
#include <hse_util/slab.h>

#include "../src/logging_impl.h"

/* --------------------------------------------------
 * scaffolding lifted from logging_test.c
 */

#undef hse_xlog
#define hse_xlog(log_fmt, hse_args, ...) hse_log_pri(log_fmt "\\n", false, hse_args, ##__VA_ARGS__)

#define MAX_MSG_SIZE 1000
#define MAX_NV_PAIRS 50
#define MAX_NV_SIZE 100

struct logging_result {
    char msg_buffer[MAX_MSG_SIZE];
    char count;
    char names[MAX_NV_PAIRS][MAX_NV_SIZE];
    char values[MAX_NV_PAIRS][MAX_NV_SIZE];
    char index;
} shared_result;

void
parse_json_key_values(char *key)
{
    char *curr_pos = NULL;
    int   i = 0, j = 0;
    int   index = 0;
    int   count = 0;

    char names[MAX_NV_SIZE];
    char values[MAX_NV_SIZE];

    curr_pos = strstr(shared_result.msg_buffer, key);
    assert(curr_pos != NULL);

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
}

void
process_json_payload(void)
{
    shared_result.index = 0;
    shared_result.count = 0;

    parse_json_key_values("hse_logver");
    parse_json_key_values("hse_version");
    parse_json_key_values("hse_branch");
    parse_json_key_values("hse_0_category");
    parse_json_key_values("hse_0_version");
    parse_json_key_values("hse_0_path");
    parse_json_key_values("hse_0_varname");
    parse_json_key_values("hse_0_value");
    parse_json_key_values("hse_0_writable");
    parse_json_key_values("hse_0_timestamp");
}

void
process_json_payload_test_ev(void)
{
    shared_result.index = 0;
    shared_result.count = 0;

    parse_json_key_values("hse_logver");
    parse_json_key_values("hse_version");
    parse_json_key_values("hse_branch");
    parse_json_key_values("hse_0_category");
    parse_json_key_values("hse_0_version");
    parse_json_key_values("hse_0_path");
    parse_json_key_values("hse_0_odometer");
    parse_json_key_values("hse_0_trip_odometer");
    parse_json_key_values("hse_0_flags");
    parse_json_key_values("hse_0_timestamp");
}

void
process_json_payload_test_fmt_string(void)
{
    shared_result.index = 0;
    shared_result.count = 0;

    parse_json_key_values("msg");
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
vsyslog(int pri, const char *fmt, va_list args)
{
    vsnprintf(shared_result.msg_buffer, MAX_MSG_SIZE, fmt, args);
}

/*
 * end of scaffolding from logging_test.c
 * --------------------------------------------------
 */

int
structured_logging_test_pre(struct mtf_test_info *ti)
{
    return 0;
}

int
structured_logging_test_post(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(
    structured_logging_test,
    structured_logging_test_pre,
    structured_logging_test_post);

MTF_DEFINE_UTEST(structured_logging_test, test_config)
{
    struct hse_config *      cfg;
    void *                   av[] = { 0, 0 };
    int                      x1 = 1;
    int                      def_x1 = 2;
    int                      ix = 0;
    struct dt_element        dte;
    struct dt_set_parameters dsp = {.value = "42", .value_len = 3, .field = DT_FIELD_DATA };

    cfg =
        CFG("laptop/lenovo",
            "carbon",
            &x1,
            sizeof(x1),
            &def_x1,
            NULL,
            NULL,
            NULL,
            NULL,
            show_s32,
            true);
    av[0] = cfg;

    /**
     * Now change the value so change_timestamp will be set
     */
    dte.dte_data = (void *)cfg;
    config_set_handler(&dte, &dsp);

    hse_xlog(HSE_ERR "[UNIT TEST] @@c", av);

    process_json_payload();

    ASSERT_EQ(10, shared_result.count);

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_branch", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_0_category", shared_result.names[ix]);
    ASSERT_STREQ("hse_config", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_version", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_path", shared_result.names[ix]);
    ASSERT_STREQ("laptop/lenovo", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_varname", shared_result.names[ix]);
    ASSERT_STREQ("carbon", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_value", shared_result.names[ix]);
    ASSERT_STREQ("0x2a", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_writable", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_timestamp", shared_result.names[ix]);
    ix++;

    ASSERT_EQ(ix, shared_result.count);
}

MTF_DEFINE_UTEST(structured_logging_test, test_ev)
{
    struct event_counter ev;
    void *               av[] = { 0, 0 };
    struct dt_element    dte;
    char                 path[200];
    int                  ix = 0;

    memset(&ev, 0, sizeof(ev));
    memset(&dte, 0, sizeof(dte));

    dte.dte_data = &ev;
    dte.dte_file = __FILE__;
    dte.dte_line = __LINE__;
    dte.dte_func = __func__;
    dte.dte_comp = "test_ev_comp";

    snprintf(
        path,
        sizeof(path),
        "%s/%s/%s/%d",
        dte.dte_comp,
        basename(dte.dte_file),
        dte.dte_func,
        dte.dte_line);

    ev.ev_dte = &dte;
    snprintf(dte.dte_path, sizeof(dte.dte_path), "%s/%s", DT_PATH_EVENT, path);
    event_counter(&dte, &ev);
    av[0] = &ev;

    hse_xlog(HSE_ERR "[UNIT TEST] @@E", av);

    dt_remove(dt_data_tree, &dte);
    process_json_payload_test_ev();

    ASSERT_EQ(10, shared_result.count);

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_branch", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_0_category", shared_result.names[ix]);
    ASSERT_STREQ("event_counter", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_version", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_path", shared_result.names[ix]);
    ASSERT_STREQ(path, shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_odometer", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_trip_odometer", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_flags", shared_result.names[ix]);
    ASSERT_STREQ("0x0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_timestamp", shared_result.names[ix]);
    ix++;

    ASSERT_EQ(ix, shared_result.count);
}

int
test_helper(char *buf, const char *fmt, ...)
{
    va_list args;
    char *  p = 0;

    va_start(args, fmt);

    buf += vsprintf(buf, fmt, args);
    buf += sprintf(buf, "\t");
    p = (char *)va_arg(args, void *);

    while (p != 0) {
        buf += sprintf(buf, "%s\t", p);
        p = (char *)va_arg(args, void *);
    }
    buf -= 1;
#pragma GCC diagnostic ignored "-Wformat-zero-length"
    sprintf(buf, "");
#pragma GCC diagnostic warning "-Wformat-zero-length"
    va_end(args);

    return 0;
}

void
test_preprocess_fmt_string(
    struct hse_log_fmt_state *state,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    ...)
{

    va_list args;

    va_start(args, hse_args);

    vpreprocess_fmt_string(state, fmt, new_fmt, new_len, hse_args, args);

    va_end(args);
}

void
test_finalize_log_structure(
    struct hse_log_fmt_state *state,
    bool                      async,
    char *                    source_file,
    s32                       source_line,
    const char *              fmt,
    char *                    new_fmt,
    s32                       new_len,
    void **                   hse_args,
    ...)
{
    va_list args;

    va_start(args, hse_args);

    vpreprocess_fmt_string(state, fmt, new_fmt, new_len, hse_args, args);

    va_end(args);

    va_start(args, hse_args);

    finalize_log_structure(1, async, source_file, source_line, state, new_fmt, args);

    va_end(args);
}

MTF_DEFINE_UTEST(structured_logging_test, Test_preprocess_fmt_string_hse)
{
    char reference[1000], scratch[1000], dict[1000];

    struct hse_log_fmt_state state;
    struct merr_info         info;

    merr_t err = merr(EINVAL);
    char   code_as_string[12];
    char   line_as_string[12];
    char   description[300];
    void **name_buf = 0, **value_buf = 0;
    int    ix = 0;

    snprintf(code_as_string, sizeof(code_as_string), "%d", merr_errno(err));
    snprintf(line_as_string, sizeof(line_as_string), "%d", merr_lineno(err));

    memset(description, 0, sizeof(char) * 64);
    merr_strerror(err, description, sizeof(description));

    static const char *const fmt = "There was an error: @@e";
    void *                   av[] = { &err, 0 };

    name_buf = malloc(sizeof(void *) * MAX_HSE_NV_PAIRS);
    ASSERT_EQ(0, !name_buf);

    value_buf = malloc(sizeof(void *) * MAX_HSE_NV_PAIRS);
    ASSERT_EQ(0, !value_buf);

    state.dict = dict;
    state.dict_pos = dict;
    state.dict_rem = sizeof(dict) - 1;
    state.names = (void *)name_buf;
    state.values = (void *)value_buf;

    state.num_hse_specs = 1;
    state.hse_spec_cnt = 0;
    state.nv_index = 0;
    state.nv_hse_index = 0;
    state.source_info_set = false;

    sprintf(reference, "There was an error: %s", merr_info(err, &info));
    test_finalize_log_structure(&state, false, __FILE__, 1, fmt, scratch, sizeof(scratch), av);

    process_json_payload_test_fmt_string();

    ix = 0;
    ASSERT_EQ(10, shared_result.count);

    ASSERT_STREQ("msg", shared_result.names[ix]);
    ASSERT_STREQ(reference, shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
    ASSERT_NE(shared_result.values[ix], NULL);
    ix++;

    ASSERT_STREQ("hse_branch", shared_result.names[ix]);
    ASSERT_NE(shared_result.values[ix], NULL);
    ix++;

    ASSERT_STREQ("hse_0_category", shared_result.names[ix]);
    ASSERT_STREQ("hse_error", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_version", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_code", shared_result.names[ix]);
    ASSERT_NE(shared_result.values[ix], NULL);
    ix++;

    ASSERT_STREQ("hse_0_file", shared_result.names[ix]);
    ASSERT_STREQ("test/structured_logging_test.c", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_line", shared_result.names[ix]);
    ASSERT_NE(shared_result.values[ix], NULL);
    ix++;

    ASSERT_STREQ("hse_0_description", shared_result.names[ix]);
    ASSERT_STREQ(description, shared_result.values[ix]);
    ix++;

    ASSERT_EQ(ix, shared_result.count);

    free(name_buf);
    free(value_buf);
}

MTF_DEFINE_UTEST(structured_logging_test, Test_multi_hse_args)
{
    /*
     * line0 and line1 are useful when debugging, to check output, but are
     * not otherwise used.
     */
    merr_t err0 = merr(EINVAL);
    /* int        line0 = __LINE__ - 1; */
    merr_t err1 = merr(ENOMEM);
    /* int        line1 = __LINE__ - 1; */
    void *av[] = { &err0, &err1, 0 };

    hse_xlog(HSE_ERR "Error 0: @@e    Error 1: @@e", av);
}

MTF_END_UTEST_COLLECTION(structured_logging_test);
