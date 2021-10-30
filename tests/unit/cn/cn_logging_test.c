/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <mtf/framework.h>
#include <hse_util/logging.h>
#include <hse_util/bloom_filter.h>
#include <hse_ikvdb/cn.h>

#include "../src/logging_impl.h"

#include <mocks/mock_log.h>

/* --------------------------------------------------
 * scaffolding lifted from logging_test.c
 */

#define hse_xlog(_fmt, _argv, ...) \
    log_pri(HSE_LOGPRI_ERR, (_fmt), false, _argv, ##__VA_ARGS__)

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
    int   i = 0;
    int   j = 0;
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
    parse_json_key_values("hse_0_hash_count");
    parse_json_key_values("hse_0_filter_size");
    parse_json_key_values("hse_0_lookup_count");
    parse_json_key_values("hse_0_hit_count");
    parse_json_key_values("hse_0_no_hit_count");
    parse_json_key_values("hse_0_hit_failed_count");
}

/*
 * end of scaffolding from logging_test.c
 * --------------------------------------------------
 */

int
cn_logging_test_pre(struct mtf_test_info *ti)
{
    merr_t err;

    err = cn_init();
    if (err)
        abort();

    return 0;
}

int
cn_logging_test_post(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PREPOST(cn_logging_test, cn_logging_test_pre, cn_logging_test_post);

MTF_DEFINE_UTEST(cn_logging_test, test_bloom)
{
    struct bloom_filter_stats stats;
    void *                    av[] = { &stats, 0 };
    char                      buffer[64];
    int                       ix = 0;

    stats.bfs_ver = 17;
    stats.bfs_filter_hashes = 13;
    stats.bfs_filter_bits = 1731;
    stats.bfs_lookup_cnt = 101;
    stats.bfs_hit_cnt = 202;
    stats.bfs_no_hit_cnt = 303;
    stats.bfs_hit_failed_cnt = 404;

    hse_gparams.gp_logging.structured = true;

    hse_xlog("[UNIT TEST] @@bsx", av);

    process_json_payload();

    ASSERT_EQ(10, shared_result.count);

    ASSERT_STREQ("hse_logver", shared_result.names[ix]);
    ASSERT_STREQ("1", shared_result.values[ix]);
    ix++;

    ASSERT_STREQ("hse_version", shared_result.names[ix]);
    ix++;

    ASSERT_STREQ("hse_0_category", shared_result.names[ix]);
    ASSERT_STREQ("bloom_stats", shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%u", stats.bfs_ver);
    ASSERT_STREQ("hse_0_version", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%u", stats.bfs_filter_hashes);
    ASSERT_STREQ("hse_0_hash_count", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%u", stats.bfs_filter_bits);
    ASSERT_STREQ("hse_0_filter_size", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%lu", stats.bfs_lookup_cnt);
    ASSERT_STREQ("hse_0_lookup_count", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%lu", stats.bfs_hit_cnt);
    ASSERT_STREQ("hse_0_hit_count", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%lu", stats.bfs_no_hit_cnt);
    ASSERT_STREQ("hse_0_no_hit_count", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    sprintf(buffer, "%lu", stats.bfs_hit_failed_cnt);
    ASSERT_STREQ("hse_0_hit_failed_count", shared_result.names[ix]);
    ASSERT_STREQ(buffer, shared_result.values[ix]);
    ix++;

    ASSERT_EQ(ix, shared_result.count);
}

/* cn registers conversion for @@w, @@k, and @@K with the logger, but all
 * of their conversion functions return false.  Since the error message
 * is sent to the backstop stop we cannot look for it in the log buffer.
 * Therefore, we use merr() to generate a unique string that should be
 * printed with the log message, and assert that the unique string did
 * not get entered into the log.
 */
MTF_DEFINE_UTEST(cn_logging_test, test_wbtree)
{
    char msgbuf[128], errbuf[128];
    merr_t err;
    void *av[] = { "test_wbtree", &err, NULL };
    char *needle;

    err = merr(EINVAL);
    snprintf(msgbuf, sizeof(msgbuf), "%s %s",
             (char *)av[0], merr_strinfo(err, errbuf, sizeof(errbuf), NULL));

    hse_xlog("[UNIT_TEST] @@w @@e", av);

    needle = strstr(shared_result.msg_buffer, msgbuf);
    ASSERT_EQ(NULL, needle);
}

MTF_DEFINE_UTEST(cn_logging_test, test_compact)
{
    char msgbuf[128], errbuf[128];
    merr_t err;
    void *av[] = { "test_compact", &err, NULL };
    char *needle;

    err = merr(EINVAL);
    snprintf(msgbuf, sizeof(msgbuf), "%s %s",
             (char *)av[0], merr_strinfo(err, errbuf, sizeof(errbuf), NULL));

    hse_xlog("[UNIT_TEST] @@k @@e", av);

    needle = strstr(shared_result.msg_buffer, msgbuf);
    ASSERT_EQ(NULL, needle);
}

MTF_DEFINE_UTEST(cn_logging_test, test_candidate)
{
    char msgbuf[128], errbuf[128];
    merr_t err;
    void *av[] = { "test_candidate", &err, NULL };
    char *needle;

    err = merr(EINVAL);
    snprintf(msgbuf, sizeof(msgbuf), "%s %s",
             (char *)av[0], merr_strinfo(err, errbuf, sizeof(errbuf), NULL));

    hse_xlog("[UNIT_TEST] @@K @@e", av);

    needle = strstr(shared_result.msg_buffer, msgbuf);
    ASSERT_EQ(NULL, needle);
}

MTF_END_UTEST_COLLECTION(cn_logging_test);
