# HSE Test Development

## Terminology

A **test suite** is a group of related tests.  Each **test** belongs
to one or more test suites and contains multiple **test cases**.  A
**benchmark** is a test designed to test HSE performance.

The following command lists each test along with their test suites.
For example, "c0_kvset_test" is part of two suites "unit" and "c0".

    $ meson test --list

    hse:unit+c0 / c0_kvset_test
    hse:unit+cn / kblock_builder_test
    hse:unit+util / hse_err_test
    hse:functional+kvpy / s00.basic
    hse:functional+smoke / simple_client1
    hse:functional+api / put_get_delete

The following commands show HSE benchmark tests:

    $ meson test --list --benchmark

    test_kmt_ro
    test_kmt_rw

Notes:
- The meson build system does not enforce a structure on test suites.
  HSE has adopted the convention of defining each test to be in the
  "unit" or "functional" suite but not both.  But one should not
  assume other suites have similar structure (for example suite "c0"
  might include tests from both "unit" and "functional" suites).
- One might think of benchmarks as another test suite, but they are
  not integrated into meson as test suites.  However, for convenience
  we sometimes refer to benchmark as a suite.

## HSE Test Development

HSE defines two top-level test suites:
- The **unit** suite tests internal APIs and modules.  Most unit tests
  focus on individual source files, but some test a set of related
  source files.  For example "hse_err_test" tests the code in
  "hse_err.c", but "kblock_builder_test" tests the kblock builder as
  well as the builders it depends on (e.g., "wbt_builder.c").
- The **functional** suite tests HSE as a whole.  Some tests in this
  suite focus on the public HSE API, while others focus on
  specific internal behaviors (e.g., cN tree shape, compaction, etc.).

In addition, HSE has **benchmark** tests that measure performance
metrics under a variety of workloads.

## Test Infrastructure

HSE test infrastructure features include:
- Test harnesses
- Test fixtures
- Support for mocking C functions
- Support for multiple languages (Python, C)

Different test suites use different features.  The general rules are:

    Suite        Harness   Fixtures   Mocking   Languages
    -----        -------   --------   -------   ---------
    Unit         yes       no         yes       C
    Functional   yes       yes        no        C, Python
    Benchmark    no        yes        no        C [1]

    [1] - Benchmarks use Python as a front end, but the
          underlying performance test is usually written in C.

## General Rules

In the following, a *test case* is a unit of code defined with the
"MTF_DEFINE_UTEST" macro.

### Verify all function results

Your test is testing other code, but there is no code to test your
test.  You can compensate for this with defensive coding practices.
Defensive code serves several purposes, among them:
- It serves as a sanity check for your logic (important because there
  is no QA team to test the test).
- It helps prevent future changes from inadvertently breaking the code.
- It builds confidence in the test (when a poorly written test fails,
   developers will think the test is at fault rather than the code under test).

Here's an example that does not check results:

    #define MAX 999
    char key[10];
    int i;

    for (i = 0; i < MAX; i++) {
        snprintf(key, sizeof(key), "key%d", i);
        hse_kvs_delete(kvs, NULL, key, keylen);
        hse_kvs_get(kvs, NULL, key, keylen, &found, vbuf, sizeof(vbuf), &vlen);
    }

The above code may work today.  But two years later if someone changes
MAX to 1000000 or changes the format string from "key%d" to "testkey%d",
the test will silently be wrong.  If it was written as shown below, such
changes would be immediately detected:

    #define MAX 999
    char key[10];
    int i, n;


    for (i = 0; i < MAX; i++) {

        n = snprintf(key, sizeof(key), "key%d", i);
        ASSERT_LT(n, sizeof(key));

        err = hse_kvs_delete(kvs, NULL, key, keylen);
        ASSERT_EQ(err, 0);

        err = hse_kvs_get(kvs, NULL, key, keylen, &found, vbuf, sizeof(vbuf), &vlen);
        ASSERT_EQ(err, 0);
    }

### Test cases should not depend on each other

There are two reasons for this rule.  First, a sequence of dependent
test cases can cause multiple test case failures when one step in the
sequence fails.  While that's not a disaster, it does make it harder
to diagnose problems when there are many cascading failures versus
just one failure.

The second and more important reason is related to test
maintainability.  It is much easier to modify a test case when there
are no dependencies on surrounding test cases.

### Each test should create its own test KVDBs and KVSes

This rule ensures test independence.

### Tests should use uniquely named KVDBs

This rule ensures tests can run concurrently.

NOTE: This rule we be enforced when we conver to libmpool.

### Each test should destroy its KVDBs and KVSes upon completion

This rule reduces the total storage needed to run tests.

### Tests should refrain from using global variables

Global variables can create inadvertent dependencies between tests
cases.  A common exception is the KVDB handle: tests typically have a
global to hold the KVDB handle so the KVDB doesn't have to be opened
closed for every test case.  But don't for example, use a global
variable to hold a cursor handle -- it would be preferable to declare
the cursor handle local to each test case and recreate the cursor.

### Test cases should be careful when reusing keys

Be careful when using the same keys across multiple tests cases.
There are scenearios where it makes perfect sense.  For example, if a
series of tests cases query a KVS, it is okay to populate the KVS in a
setup fixture and reuse the keys in multiple tests cases.  But if some
test cases add or delete keys, and later test cases read them, then
you have dependency between test cases.  In that case, it would be
more robust to use non-overlapping keys or even different KVSes.

### Avoid test duplication

Don't create two tests for the same functionality unless they each add
their own value.  We already have a fair amount of duplication in our
smoke tests (how many ways do we need to put and get keys?).

### Use MTF fixtures

See [put_get_delete.c](../tests/functional/api/put_get_delete.c)
makes use of *mtf_kvdb_setup()* and *mtf_kvdb_teardown()*.

### Prefer ASSERT_EQ / ASSERT_LT / etc over ASSERT_TRUE

The following are equivalent from a correctness point of view:

    ASSERT_EQ(actual, expected);

    ASSERT_TRUE(actual == expected);

But when they fail, *ASSERT_EQ* will print the values of *actual* and *expected*,
while *ASSERT_TRUE* will only be able to print "the expression was false".

### Use ASSERT_XX_RET macros in helper functions

If you pass *struct mtf_test_info \*lcl_ti* to helper functions, you
can use *ASSERT* macros and get better diagnostics when tests fail.

Things to remember:
- The *ASSERT* macros assume existence of local var *struct mtf_test_info \*lcl_ti*.
- The *ASSERT_XX_RET* macros return type *int*, while the *ASSERT_XX* macros return type *void*.

See [put_get_delete.c](../tests/functional/api/put_get_delete.c) for an example.

### Don't use hse_err_to_errno() if you simply want to verify success

Good:
    err = hse_kvdb_kvs_close(kvs);
    ASSERT_EQ(err, 0);

Not "bad", but harder to read:

    err = hse_kvdb_kvs_close(kvs);
    ASSERT_EQ(hse_err_to_errno(err), 0);



### Use the correct type to store return values

Good:

    hse_err_t err;
    int rc;

    err = hse_kvdb_kvs_close(kvs);
    ASSERT_EQ(err, 0);

    rc = mtf_kvdb_teardown(lcl_ti);
    ASSERT_EQ(rc, 0);

Bad:

    int rc;

    rc = hse_kvdb_kvs_close(kvs);   // WRONG TYPE
    ASSERT_EQ(rc, 0);

    rc = mtf_kvdb_teardown(lcl_ti);
    ASSERT_EQ(rc, 0);

### Use constants if it improves readability

Declaring a variable like this:

    const char *kvs_name = "#####";

And then using it 50 lines away from where it was declared:

    /* test invalid kvs name */
    err = hse_kvdb_kvs_create(kvdb, kvs_name, NULL);
    ASSERT_EQ(err, 0);

Is harder to follow than this:

    /* test invalid kvs name */
    err = hse_kvdb_kvs_create(kvdb, "#####", NULL);
    ASSERT_EQ(err, 0);
