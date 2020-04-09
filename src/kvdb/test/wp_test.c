/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#define _GNU_SOURCE /* for asprintf() */

#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>

#include <hse_ut/framework.h>
#include <hse_ut/common.h>

#include <hse_util/data_tree.h>

#include <hse_ikvdb/wp.h>

#define BUF_SZ 512

char path[BUF_SZ];

#define TEST_NAME "wp_test"
const char *example_profiles_dir;

#define FILE_LIST_MAX 64
struct file_list {
    char *       files[FILE_LIST_MAX];
    unsigned int files_cnt;
};

/* return -1 on error, 0 on success */
static void
flist_init(struct file_list *fl)
{
    memset(fl, 0, sizeof(*fl));
}

static int
flist_append(struct file_list *fl, const char *dir, const char *file)
{
    int rc;

    if (fl->files_cnt == NELEM(fl->files))
        return -1;

    if (!dir || !file)
        return -1;

    rc = asprintf(&fl->files[fl->files_cnt], "%s/%s", dir, file);
    if (rc == -1)
        return -1;

    fl->files_cnt++;
    return 0;
}

static void
flist_free(struct file_list *fl)
{
    unsigned int i;

    for (i = 0; i < NELEM(fl->files); i++)
        free(fl->files[i]);
}

static int
get_profiles(struct file_list *fl, const char *dirname)
{
    struct dirent *ent;
    size_t         len;
    DIR *          dir;

    dir = opendir(dirname);
    if (!dir) {
        fprintf(stderr, "Cannot open dir: %s\n", dirname);
        return -1;
    }

    while (NULL != (ent = readdir(dir))) {

        if (ent->d_type != DT_REG)
            continue;

        if (ent->d_name[0] == '.')
            continue;

        len = strlen(ent->d_name);
        if (len <= 4 || strcmp(ent->d_name + len - 4, ".yml"))
            continue;

        if (flist_append(fl, dirname, ent->d_name))
            return -1;
    }

    closedir(dir);
    return 0;
}

int
write_to_file(const char *content)
{
    FILE *fp;

    fp = fopen(path, "w");
    if (!fp)
        return -1;
    fprintf(fp, "%s\n", content);
    fclose(fp);
    return 0;
}

int
setup(struct mtf_test_info *lcl_ti)
{
    int   rc;
    char *result;
    char template[] = "/tmp/hse_utest.XXXXXX";
    int    argc = lcl_ti->ti_coll->tci_argc;
    char **argv = lcl_ti->ti_coll->tci_argv;

    hse_openlog(TEST_NAME, 1);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <profile_dir>\n", TEST_NAME);
        return 1;
    }

    example_profiles_dir = argv[1];

    result = mkdtemp(template);
    if (!result)
        return 1;

    rc = snprintf(path, sizeof(path), "%s/kvdb_test.yaml", result);
    if (rc > sizeof(path))
        return 1;

    return 0;
}

MTF_MODULE_UNDER_TEST(wp);

MTF_BEGIN_UTEST_COLLECTION_PRE(wp, setup);

MTF_DEFINE_UTEST(wp, parser_invalid_config)
{
    int                rc;
    char               profile[BUF_SZ];
    struct hse_params *params;
    merr_t             err;

    /* empty file */
    rc = snprintf(profile, sizeof(profile), " ");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    /* no kvdb or kvs section */
    rc = snprintf(profile, sizeof(profile), "apiVersion: 1");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_EQ(err, NULL);
    hse_params_destroy(params);

    /* empty kvdb section */
    rc = snprintf(profile, sizeof(profile), "kvdb:");
    ASSERT_LT(rc, sizeof(profile));
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    /* empty kvs section */
    rc = snprintf(profile, sizeof(profile), "kvs:");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(wp, parser_kvdb_section)
{
    int                rc;
    merr_t             err;
    struct hse_params *params;
    char               base[BUF_SZ];
    char               profile[BUF_SZ];
    char               buf[32];
    char *             result;

    /* base profile */
    rc = snprintf(base, sizeof(base), "apiVersion: 1\nkvdb:\n  ");
    ASSERT_LT(rc, sizeof(base));

    /* invalid field */
    rc = snprintf(profile, sizeof(profile), "%s%s", base, "money: 100000");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    /* cparams */
    rc = snprintf(profile, sizeof(profile), "%s%s", base, "super_cool: 55");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    rc = snprintf(profile, sizeof(profile), "%s%s", base, "dur_intvl_ms: 100");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_EQ(err, NULL);

    result = hse_params_get(params, "kvdb.dur_intvl_ms", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "100"), 0);
    hse_params_destroy(params);

    /* rparams */
    rc = snprintf(profile, sizeof(profile), "%s%s", base, "reduce_power: 1");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    rc = snprintf(profile, sizeof(profile), "%s%s", base, "low_mem: 1");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_EQ(err, NULL);

    result = hse_params_get(params, "kvdb.low_mem", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "1"), 0);
    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(wp, parser_kvs_section)
{
    int                rc;
    merr_t             err;
    struct hse_params *params;
    char               base[BUF_SZ];
    char               profile[BUF_SZ];
    char               buf[32];
    char *             result;

    /* base profile */
    rc = snprintf(base, sizeof(base), "apiVersion: 1\nkvs.kvs_test:\n  ");
    ASSERT_LT(rc, sizeof(base));

    /* invalid field */
    rc = snprintf(profile, sizeof(profile), "%s%s", base, "answer: 42");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    /* cparams */
    rc = snprintf(profile, sizeof(profile), "%s%s", base, "fanin: 8");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    rc = snprintf(profile, sizeof(profile), "%s%s", base, "fanout: 8");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_EQ(err, NULL);

    result = hse_params_get(params, "kvs.kvs_test.fanout", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "8"), 0);
    hse_params_destroy(params);

    /* rparams */
    rc = snprintf(profile, sizeof(profile), "%s%s", base, "pause: 5");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_NE(err, NULL);
    hse_params_destroy(params);

    rc = snprintf(profile, sizeof(profile), "%s%s", base, "cn_bloom_create: 0");
    ASSERT_LT(rc, sizeof(profile));
    write_to_file(profile);

    hse_params_create(&params);
    err = wp_parse(path, params, WP_FILE);
    ASSERT_EQ(err, NULL);

    result = hse_params_get(params, "kvs.kvs_test.cn_bloom_create", buf, sizeof(buf), 0);
    ASSERT_NE(result, NULL);
    ASSERT_EQ(strcmp(result, "0"), 0);
    hse_params_destroy(params);
}

MTF_DEFINE_UTEST(wp, wp_examples)
{
    int                rc;
    merr_t             err;
    unsigned int       i;
    struct hse_params *params;
    struct file_list   fl;

    hse_log(HSE_DEBUG "Testing profiles in %s", example_profiles_dir);

    flist_init(&fl);
    rc = get_profiles(&fl, example_profiles_dir);
    ASSERT_EQ(rc, 0);
    ASSERT_GT(fl.files_cnt, 0);

    for (i = 0; i < fl.files_cnt; i++) {
        hse_log(HSE_DEBUG "Testing: %s", fl.files[i]);

        hse_params_create(&params);

        err = wp_parse(fl.files[i], params, WP_FILE);
        ASSERT_EQ(err, 0);

        hse_params_destroy(params);
    }

    flist_free(&fl);
}

MTF_END_UTEST_COLLECTION(wp)
