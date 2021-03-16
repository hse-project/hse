#ifndef HSE_FUNTEST_H
#define HSE_FUNTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hse/hse.h>

struct ft_collection {
    int (*before)();
    bool (*assert)(hse_err_t, int);
    hse_err_t (*after)();
    int passed;
    int failed;
};

void
init_test(struct ft_collection *test, int (*before)(), bool (*assert)(hse_err_t, int), hse_err_t (*after)())
{
    test->before = before;
    test->assert = assert;
    test->after = after;
    test->passed = 0;
    test->failed = 0;
}

hse_err_t
execute_testcase(struct ft_collection *test, char *behavior, hse_err_t (*testcase)(), int expected)
{
    int       rc;
    hse_err_t result;
    bool      valid;

    if (behavior != NULL)
        printf("\n%s\n", behavior);

    rc = test->before();
    if (rc) {
        fprintf(stderr, "SETUP FAILED: %s (%d)\n", strerror(rc), rc);
        exit(1);
    }

    result = testcase();
    valid = test->assert(result, expected);
    valid ? test->passed++ : test->failed++;

    rc = test->after();
    if (rc) {
        fprintf(stderr, "TEARDOWN FAILED: %s (%d)\n", strerror(rc), rc);
        exit(1);
    }

    return result;
}

bool
assert_errno(hse_err_t result, int expected)
{
    char buf[128];
    hse_err_to_string(result, buf, sizeof(buf), NULL);

    if (hse_err_to_errno(result) == expected) {
        printf("PASSED: %s (%d)\n", buf, expected);
        return true;
    }

    fprintf(stderr, "FAILED: %s (%d)\n", buf, hse_err_to_errno(result));
    printf("FAILED: %s (%d)\n", buf, hse_err_to_errno(result));
    printf("EXPECTED: %s (%d)\n", strerror(expected), expected);
    return false;
}

#endif
