#ifndef HSE_FUNTEST_H
#define HSE_FUNTEST_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hse/hse.h>

struct ft_collection {
    int (*before)();
    bool (*assert)(hse_err_t, int, char *);
    hse_err_t (*after)();
    int passed;
    int failed;
};

void
init_test(struct ft_collection *test, int (*before)(), bool (*assert)(hse_err_t, int, char *), hse_err_t (*after)())
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
    hse_err_t result, rc;
    bool      valid;

    rc = test->before();
    if (rc) {
        fprintf(stderr, "SETUP FAILED: %s (%d)\n", strerror(rc), hse_err_to_errno(rc));
        exit(1);
    }

    result = testcase();
    valid = test->assert(result, expected, behavior);
    valid ? test->passed++ : test->failed++;

    rc = test->after();
    if (rc) {
        fprintf(stderr, "TEARDOWN FAILED: %s (%d)\n", strerror(rc), hse_err_to_errno(rc));
        exit(1);
    }

    return result;
}

bool
assert_errno(hse_err_t result, int expected, char *behavior)
{
    char buf[128];
    hse_err_to_string(result, buf, sizeof(buf), NULL);

    if (hse_err_to_errno(result) == expected) {
        printf("\n%s\n", behavior);
        printf("PASSED: %s (%d)\n", buf, expected);
        return true;
    }
    
    fprintf(stderr, "\n%s\n", behavior);
    fprintf(stderr, "FAILED: %s (%d)\n", buf, hse_err_to_errno(result));
    fprintf(stderr, "EXPECTED: %s (%d)\n", strerror(expected), expected);
    return false;
}

#endif
