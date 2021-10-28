/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/logging.h>
#include <hse_util/hse_err.h>
#include <hse_util/data_tree.h>
#include <hse_util/slab.h>

#include "../src/logging_impl.h"

#include <mocks/mock_log.h>

/* --------------------------------------------------
 * scaffolding lifted from logging_test.c
 */

#define hse_xlog(_fmt, _argv, ...) \
    log_pri(HSE_LOGPRI_ERR, _fmt, false, _argv, ##__VA_ARGS__)

void
hse_slog_emit(hse_logpri_t priority, const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(shared_result.msg_buffer, MAX_MSG_SIZE, fmt, ap);
    va_end(ap);
}

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
    if (!curr_pos)
        abort();

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
    hse_gparams.gp_logging.structured = true;
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

MTF_DEFINE_UTEST(structured_logging_test, test_ev)
{
    static struct event_counter ev = {
        .ev_odometer = ATOMIC_INIT(0),
        .ev_pri = HSE_LOGPRI_DEBUG,
        .ev_flags = EV_FLAGS_HSE_LOG,
        .ev_file = __FILE__,
        .ev_line = __LINE__,
        .ev_dte = {
            .dte_data = &ev,
            .dte_ops = &event_counter_ops,
            .dte_type = DT_TYPE_ERROR_COUNTER,
            .dte_file = __FILE__,
            .dte_line = __LINE__,
            .dte_func = __func__,
        }
    };
    void *av[] = { NULL, NULL };
    int ix = 0;
    int rc;

    event_counter(&ev);
    av[0] = &ev;

    hse_xlog("[UNIT TEST] @@E", av);

    rc = dt_remove(&ev.ev_dte);
    ASSERT_NE(0, rc);

    process_json_payload_test_ev();

    ASSERT_EQ(9, shared_result.count);

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_0_category", shared_result.names[ix]);
    ASSERT_STREQ("event_counter", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_version", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_path", shared_result.names[ix]);
    ASSERT_NE(NULL, strstr(ev.ev_dte.dte_path, shared_result.values[ix]));
    ix++;

    ASSERT_STREQ("hse_0_odometer", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_trip_odometer", shared_result.names[ix]);
    ASSERT_STREQ("0", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_0_flags", shared_result.names[ix]);
    ASSERT_STREQ("0x1", shared_result.values[ix]);
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
    ASSERT_EQ(9, shared_result.count);

    ASSERT_STREQ("msg", shared_result.names[ix]);
    ASSERT_NE(NULL, strstr(shared_result.values[ix], reference));
    ix++;

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
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
    ASSERT_NE(NULL, strstr(__FILE__, shared_result.values[ix]));
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

    hse_xlog("Error 0: @@e    Error 1: @@e", av);
}

MTF_END_UTEST_COLLECTION(structured_logging_test);
