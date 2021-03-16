#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <hse/hse.h>
#include <hse_ft/ft_framework.h>

/* Globals */
char *           MPOOL_NAME;
const char *     KVS_NAME = "kvs_test";
struct hse_kvdb *KVDB_HANDLE = NULL;

/* Temp Workaround for SBUSWNF-1438 */
hse_err_t
safe_kvdb_make(void)
{
    int i;
    hse_err_t rc;

    for (i = 0; i < 10; i++) {
        rc = hse_kvdb_make(MPOOL_NAME, NULL);
        if (!hse_err_to_errno(rc))
            break;
        sleep(1);
    }

    return rc;
}

/* Function Level */
int
do_nothing(void)
{
    return EXIT_SUCCESS;
}

int
kvdb_required(void)
{
    return safe_kvdb_make();
}

hse_err_t
cleanup(void)
{
    hse_err_t rc;

    if (KVDB_HANDLE != NULL) {
        rc = hse_kvdb_close(KVDB_HANDLE);
        if (rc)
            return rc;

        KVDB_HANDLE = NULL;
    }

    return EXIT_SUCCESS;
}

/* Session Level */
void
before_all(struct ft_collection *clean_test)
{
    int rc;

    init_test(clean_test, &do_nothing, &assert_errno, &cleanup);

    rc = hse_kvdb_init();
    if (rc) {
        fprintf(stderr, "before_all: failed to initialize kvdb\n");
        exit(1);
    }
}

void
after_all(void)
{
    hse_kvdb_fini();
}

/* KVDB API Testcases */
hse_err_t
kvdb_make_testcase(void)
{
    return hse_kvdb_make(MPOOL_NAME, NULL);
}

hse_err_t
kvdb_make_testcase_no_mpool(void)
{
    return hse_kvdb_make("fake_mpool", NULL);
}

hse_err_t
kvdb_make_testcase_special_char(void)
{
    return hse_kvdb_make(MPOOL_NAME, NULL);
}

hse_err_t
kvdb_make_testcase_no_char(void)
{
    return hse_kvdb_make(MPOOL_NAME, NULL);
}

hse_err_t
kvdb_make_testcase_31_char(void)
{
    return hse_kvdb_make(MPOOL_NAME, NULL);
}

hse_err_t
kvdb_open_testcase_no_mpool(void)
{
    return hse_kvdb_open("fake_mpool", NULL, &KVDB_HANDLE) == 0 ? 0 : ENOENT;
}

hse_err_t
kvdb_open_testcase(void)
{
    return hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE) == 0 ? 0 : ENOENT;
}

hse_err_t
kvdb_open_testcase_reuse_handle(void)
{
    hse_err_t rc;

    rc = hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE);
    if (rc)
        return rc;

    return hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE);
}

hse_err_t
kvdb_valid_handle_testcase(void)
{
    hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE);
    return KVDB_HANDLE == NULL ? ENOENT : EXIT_SUCCESS;
}

hse_err_t
kvdb_close_testcase(void)
{
    hse_err_t rc;

    rc = hse_kvdb_open(MPOOL_NAME, NULL, &KVDB_HANDLE);
    if (rc)
        return rc;

    rc = hse_kvdb_close(KVDB_HANDLE);
    KVDB_HANDLE = NULL;
    return rc;
}

hse_err_t
kvdb_close_testcase_no_kvdb(void)
{
    return hse_kvdb_close(KVDB_HANDLE) == 0 ? 0 : EINVAL;
}

int
main(int argc, char *argv[])
{
    struct ft_collection clean_test;
    hse_err_t   err;
    MPOOL_NAME = argv[1];

    printf("------------------------\n");
    printf("RUNNING TESTCASES\n");
    printf("mpool = %s\n", MPOOL_NAME);
    printf("------------------------\n");

    before_all(&clean_test);

    err = execute_testcase(
        &clean_test,
        "TC: A KVDB with a valid name can be created on an existing MPOOL...",
        &kvdb_make_testcase,
        EXIT_SUCCESS);

    if (hse_err_to_errno(err) == EACCES) {
        fprintf(stderr, "Invalid permissions");
        exit(1);
    }

    execute_testcase(
        &clean_test,
        "TC: A non-existing KVDB cannot be opened...",
        &kvdb_open_testcase_no_mpool,
        ENOENT);

    execute_testcase(
        &clean_test,
        "TC: A non-existing KVDB cannot be closed...",
        &kvdb_close_testcase_no_kvdb,
        EINVAL);

    execute_testcase(
        &clean_test,
        "TC: A KVDB cannot be created on a non-existing MPOOL...",
        &kvdb_make_testcase_no_mpool,
        ENOENT);

    execute_testcase(
        &clean_test,
        "TC: An existing KVDB which is open can be closed...",
        &kvdb_close_testcase,
        EXIT_SUCCESS);

    execute_testcase(
        &clean_test, "TC: An existing KVDB can be opened...", &kvdb_open_testcase, EXIT_SUCCESS);

    execute_testcase(
        &clean_test,
        "TC: An opened KVDB returns a valid handle...",
        &kvdb_valid_handle_testcase,
        EXIT_SUCCESS);

    after_all();

    printf("\n------------------------\n");
    printf("SUMMARY - kvdb_api_tests:\n");
    printf("Passed: %d\n", clean_test.passed);
    printf("Failed: %d\n", clean_test.failed);
    printf("------------------------\n");

    return clean_test.failed > 0;
}
