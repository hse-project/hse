/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#ifndef MTF_CONDITIONS_H
#define MTF_CONDITIONS_H

#include <stdlib.h>

#include "common.h"

void
mtf_test_failure(void);

/* Set the mtf_verify_flag when the verify check fails the first time and record
 * file/line info. Subsequent failures are likely to be duplicates or collateral
 * damage resulting from the first failure. mtf_verify_flag is cleared at the
 * beginning of each unit test. */
#define ___MTF_VERIFY_INNER(cond, rc)                 \
    do {                                              \
        if (mtf_verify_flag || !(cond)) {             \
            if (!mtf_verify_flag) {                   \
                mtf_verify_flag = 1;                  \
                mtf_verify_file = REL_FILE(__FILE__); \
                mtf_verify_line = __LINE__;           \
                mtf_test_failure();                   \
            }                                         \
            return rc;                                \
        }                                             \
    } while (0)

/* The ASSERT and EXPECT macros check mtf_verify_flag first to fail fast. */
#define ___MTF_INNER_TRUE(assert, cond, rc)                                       \
    do {                                                                          \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                         \
                                                                                  \
        tci = tci;                                                                \
        if (!(cond) || mtf_verify_flag) {                                         \
            if (!mtf_verify_flag) {                                               \
                mtf_print(tci, "%s:%d: Failure\n", REL_FILE(__FILE__), __LINE__); \
                mtf_print(tci, "\texpected true: %s\n", #cond);                   \
                mtf_test_failure();                                               \
            }                                                                     \
            lcl_ti->ti_status = 0;                                                \
            if (assert)                                                           \
                return rc;                                                        \
        } else {                                                                  \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                        \
        }                                                                         \
    } while (0)

#define ___MTF_VERIFY_TRUE(cond, rc) ___MTF_VERIFY_INNER((cond), rc)

#define EXPECT_TRUE(cond) EXPECT_TRUE_RET(cond, )
#define ASSERT_TRUE(cond) ASSERT_TRUE_RET(cond, )
#define VERIFY_TRUE(cond) VERIFY_TRUE_RET(cond, )

#define EXPECT_TRUE_RET(cond, rc) ___MTF_INNER_TRUE(0, cond, rc)
#define ASSERT_TRUE_RET(cond, rc) ___MTF_INNER_TRUE(1, cond, rc)
#define VERIFY_TRUE_RET(cond, rc) ___MTF_VERIFY_TRUE(cond, rc)

#define ___MTF_INNER_FALSE(assert, cond, rc)                            \
    do {                                                                \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;               \
                                                                        \
        tci = tci;                                                      \
        if ((cond) || mtf_verify_flag) {                                \
            if (!mtf_verify_flag) {                                     \
                mtf_print(tci, "%s:%d: Failure\n", __FILE__, __LINE__); \
                mtf_print(tci, "\texpected false: %s\n", #cond);        \
                mtf_test_failure();                                     \
            }                                                           \
            lcl_ti->ti_status = 0;                                      \
            if (assert)                                                 \
                return rc;                                              \
        } else {                                                        \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;              \
        }                                                               \
    } while (0)

#define ___MTF_VERIFY_FALSE(cond, rc) ___MTF_VERIFY_INNER((!(cond)), rc)

#define EXPECT_FALSE(cond) EXPECT_FALSE_RET(cond, )
#define ASSERT_FALSE(cond) ASSERT_FALSE_RET(cond, )
#define VERIFY_FALSE(cond) VERIFY_FALSE_RET(cond, )

#define EXPECT_FALSE_RET(cond, rc) ___MTF_INNER_FALSE(0, cond, rc)
#define ASSERT_FALSE_RET(cond, rc) ___MTF_INNER_FALSE(1, cond, rc)
#define VERIFY_FALSE_RET(cond, rc) ___MTF_VERIFY_FALSE(cond, rc)

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_EQ(assert, reference, actual, rc)                                             \
    do {                                                                                           \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                          \
        __typeof__(actual) ___mtf_val = (actual);                                                  \
                                                                                                   \
        tci = tci;                                                                                 \
        if (mtf_verify_flag || (__typeof__(actual))(reference) != (___mtf_val)) {                  \
            if (!mtf_verify_flag) {                                                                \
                mtf_print(                                                                         \
                    tci, "%s:%d: Failure %s == %s\n", REL_FILE(__FILE__), __LINE__, #reference,    \
                    #actual);                                                                      \
                mtf_print(tci, "\t%ld == %ld --> false\n", (long)(reference), (long)(___mtf_val)); \
                mtf_test_failure();                                                                \
            }                                                                                      \
            lcl_ti->ti_status = 0;                                                                 \
            if (assert)                                                                            \
                return rc;                                                                         \
        } else {                                                                                   \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                         \
        }                                                                                          \
    } while (0)

#define ___MTF_VERIFY_EQ(reference, actual, rc) ___MTF_VERIFY_INNER(((reference) == (actual)), rc)

#define EXPECT_EQ(reference, actual) EXPECT_EQ_RET(reference, actual, )
#define ASSERT_EQ(reference, actual) ASSERT_EQ_RET(reference, actual, )
#define VERIFY_EQ(reference, actual) VERIFY_EQ_RET(reference, actual, )

#define EXPECT_EQ_RET(reference, actual, rc) ___MTF_INNER_EQ(0, (reference), (actual), rc)
#define ASSERT_EQ_RET(reference, actual, rc) ___MTF_INNER_EQ(1, (reference), (actual), rc)
#define VERIFY_EQ_RET(reference, actual, rc) ___MTF_VERIFY_EQ((reference), (actual), rc)

#define ___MTF_INNER_NE(assert, reference, actual, rc)                                             \
    do {                                                                                           \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                          \
        __typeof__(actual) ___mtf_val = (actual);                                                  \
                                                                                                   \
        tci = tci;                                                                                 \
        if (mtf_verify_flag || ((__typeof__(actual))(reference) == (___mtf_val))) {                \
            if (!mtf_verify_flag) {                                                                \
                mtf_print(                                                                         \
                    tci, "%s:%d: Failure %s == %s\n", REL_FILE(__FILE__), __LINE__, #reference,    \
                    #actual);                                                                      \
                mtf_print(tci, "\t%ld != %ld --> false\n", (long)(reference), (long)(___mtf_val)); \
                mtf_test_failure();                                                                \
            }                                                                                      \
            lcl_ti->ti_status = 0;                                                                 \
            if (assert)                                                                            \
                return rc;                                                                         \
        } else {                                                                                   \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                         \
        }                                                                                          \
    } while (0)

#define ___MTF_VERIFY_NE(reference, actual, rc) ___MTF_VERIFY_INNER(((reference) != (actual)), rc)

#define EXPECT_NE(reference, actual) EXPECT_NE_RET(reference, actual, )
#define ASSERT_NE(reference, actual) ASSERT_NE_RET(reference, actual, )
#define VERIFY_NE(reference, actual) VERIFY_NE_RET(reference, actual, )

#define EXPECT_NE_RET(reference, actual, rc) ___MTF_INNER_NE(0, (reference), (actual), rc)
#define ASSERT_NE_RET(reference, actual, rc) ___MTF_INNER_NE(1, (reference), (actual), rc)
#define VERIFY_NE_RET(reference, actual, rc) ___MTF_VERIFY_NE((reference), (actual), rc)

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_LT(assert, reference, actual, rc)                                            \
    do {                                                                                          \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                         \
        __typeof__(actual) ___mtf_val = (actual);                                                 \
                                                                                                  \
        tci = tci;                                                                                \
        if (mtf_verify_flag || !((__typeof__(actual))(reference) < (___mtf_val))) {               \
            if (!mtf_verify_flag) {                                                               \
                mtf_print(                                                                        \
                    tci, "%s:%d: Failure %s == %s\n", __FILE__, __LINE__, #reference, #actual);   \
                mtf_print(tci, "\t%ld < %ld --> false\n", (long)(reference), (long)(___mtf_val)); \
                mtf_test_failure();                                                               \
            }                                                                                     \
            lcl_ti->ti_status = 0;                                                                \
            if (assert)                                                                           \
                return rc;                                                                        \
        } else {                                                                                  \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                        \
        }                                                                                         \
    } while (0)

#define ___MTF_VERIFY_LT(reference, actual, rc) ___MTF_VERIFY_INNER(((reference) < (actual)), rc)

#define EXPECT_LT(reference, actual) EXPECT_LT_RET(reference, actual, )
#define ASSERT_LT(reference, actual) ASSERT_LT_RET(reference, actual, )
#define VERIFY_LT(reference, actual) VERIFY_LT_RET(reference, actual, )

#define EXPECT_LT_RET(reference, actual, rc) ___MTF_INNER_LT(0, (reference), (actual), rc)
#define ASSERT_LT_RET(reference, actual, rc) ___MTF_INNER_LT(1, (reference), (actual), rc)
#define VERIFY_LT_RET(reference, actual, rc) ___MTF_VERIFY_LT((reference), (actual), rc)

#define ___MTF_INNER_LE(assert, reference, actual, rc)                                             \
    do {                                                                                           \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                          \
        __typeof__(actual) ___mtf_val = (actual);                                                  \
                                                                                                   \
        tci = tci;                                                                                 \
        if (mtf_verify_flag || !((__typeof__(actual))(reference) <= (___mtf_val))) {               \
            if (!mtf_verify_flag) {                                                                \
                mtf_print(                                                                         \
                    tci, "%s:%d: Failure %s == %s\n", __FILE__, __LINE__, #reference, #actual);    \
                mtf_print(tci, "\t%ld <= %ld --> false\n", (long)(reference), (long)(___mtf_val)); \
                mtf_test_failure();                                                                \
            }                                                                                      \
            lcl_ti->ti_status = 0;                                                                 \
            if (assert)                                                                            \
                return rc;                                                                         \
        } else {                                                                                   \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                         \
        }                                                                                          \
    } while (0)

#define ___MTF_VERIFY_LE(reference, actual, rc) ___MTF_VERIFY_INNER(((reference) <= (actual)), rc)

#define EXPECT_LE(reference, actual) EXPECT_LE_RET(reference, actual, )
#define ASSERT_LE(reference, actual) ASSERT_LE_RET(reference, actual, )
#define VERIFY_LE(reference, actual) VERIFY_LE_RET(reference, actual, )

#define EXPECT_LE_RET(reference, actual, rc) ___MTF_INNER_LE(0, (reference), (actual), rc)
#define ASSERT_LE_RET(reference, actual, rc) ___MTF_INNER_LE(1, (reference), (actual), rc)
#define VERIFY_LE_RET(reference, actual, rc) ___MTF_VERIFY_LE((reference), (actual), rc)

#define ___MTF_INNER_GT(assert, reference, actual, rc)                                            \
    do {                                                                                          \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                         \
        __typeof__(actual) ___mtf_val = (actual);                                                 \
                                                                                                  \
        tci = tci;                                                                                \
        if (mtf_verify_flag || !((__typeof__(actual))(reference) > (___mtf_val))) {               \
            if (!mtf_verify_flag) {                                                               \
                mtf_print(                                                                        \
                    tci, "%s:%d: Failure %s == %s\n", __FILE__, __LINE__, #reference, #actual);   \
                mtf_print(tci, "\t%ld > %ld --> false\n", (long)(reference), (long)(___mtf_val)); \
                mtf_test_failure();                                                               \
            }                                                                                     \
            lcl_ti->ti_status = 0;                                                                \
            if (assert)                                                                           \
                return rc;                                                                        \
        } else {                                                                                  \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                        \
        }                                                                                         \
    } while (0)

#define ___MTF_VERIFY_GT(reference, actual, rc) ___MTF_VERIFY_INNER(((reference) > (actual)), rc)

#define EXPECT_GT(reference, actual) EXPECT_GT_RET(reference, actual, )
#define ASSERT_GT(reference, actual) ASSERT_GT_RET(reference, actual, )
#define VERIFY_GT(reference, actual) VERIFY_GT_RET(reference, actual, )

#define EXPECT_GT_RET(reference, actual, rc) ___MTF_INNER_GT(0, (reference), (actual), rc)
#define ASSERT_GT_RET(reference, actual, rc) ___MTF_INNER_GT(1, (reference), (actual), rc)
#define VERIFY_GT_RET(reference, actual, rc) ___MTF_VERIFY_GT((reference), (actual), rc)

#define ___MTF_INNER_GE(assert, reference, actual, rc)                                             \
    do {                                                                                           \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                          \
        __typeof__(actual) ___mtf_val = (actual);                                                  \
                                                                                                   \
        tci = tci;                                                                                 \
        if (mtf_verify_flag || !((__typeof__(actual))(reference) >= (___mtf_val))) {               \
            if (!mtf_verify_flag) {                                                                \
                mtf_print(                                                                         \
                    tci, "%s:%d: Failure %s == %s\n", __FILE__, __LINE__, #reference, #actual);    \
                mtf_print(tci, "\t%ld >= %ld --> false\n", (long)(reference), (long)(___mtf_val)); \
                mtf_test_failure();                                                                \
            }                                                                                      \
            lcl_ti->ti_status = 0;                                                                 \
            if (assert)                                                                            \
                return rc;                                                                         \
        } else {                                                                                   \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                         \
        }                                                                                          \
    } while (0)

#define ___MTF_VERIFY_GE(reference, actual, rc) ___MTF_VERIFY_INNER(((reference) >= (actual)), rc)

#define EXPECT_GE(reference, actual) EXPECT_GE_RET(reference, actual, )
#define ASSERT_GE(reference, actual) ASSERT_GE_RET(reference, actual, )
#define VERIFY_GE(reference, actual) VERIFY_GE_RET(reference, actual, )

#define EXPECT_GE_RET(reference, actual, rc) ___MTF_INNER_GE(0, (reference), (actual), rc)
#define ASSERT_GE_RET(reference, actual, rc) ___MTF_INNER_GE(1, (reference), (actual), rc)
#define VERIFY_GE_RET(reference, actual, rc) ___MTF_VERIFY_GE((reference), (actual), rc)

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_STREQ(assert, reference, actual, rc)                                      \
    do {                                                                                       \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                      \
        int result = strcmp(reference, actual);                                                \
                                                                                               \
        tci = tci;                                                                             \
        if (mtf_verify_flag || (result != 0)) {                                                \
            if (!mtf_verify_flag) {                                                            \
                mtf_print(                                                                     \
                    tci, "\n\ttest %s failed at line %d, %s == %s --> false", lcl_ti->ti_name, \
                    __LINE__, (reference), (actual));                                          \
                mtf_test_failure();                                                            \
            }                                                                                  \
            lcl_ti->ti_status = 0;                                                             \
            if (assert)                                                                        \
                return rc;                                                                     \
        } else {                                                                               \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                     \
        }                                                                                      \
    } while (0)

#define ___MTF_VERIFY_STREQ(reference, actual, rc) \
    ___MTF_VERIFY_INNER((strcmp((reference), (actual)) == 0), rc)

#define EXPECT_STREQ(reference, actual) EXPECT_STREQ_RET(reference, actual, )
#define ASSERT_STREQ(reference, actual) ASSERT_STREQ_RET(reference, actual, )
#define VERIFY_STREQ(reference, actual) VERIFY_STREQ_RET(reference, actual, )

#define EXPECT_STREQ_RET(reference, actual, rc) ___MTF_INNER_STREQ(0, (reference), (actual), rc)

#define ASSERT_STREQ_RET(reference, actual, rc) ___MTF_INNER_STREQ(1, (reference), (actual), rc)

#define VERIFY_STREQ_RET(reference, actual, rc) ___MTF_VERIFY_STREQ((reference), (actual), rc)

#define ___MTF_INNER_STRNE(assert, reference, actual, rc)                                      \
    do {                                                                                       \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                      \
        int result = strcmp(reference, actual);                                                \
                                                                                               \
        tci = tci;                                                                             \
        if (mtf_verify_flag || (result == 0)) {                                                \
            if (!mtf_verify_flag) {                                                            \
                mtf_print(                                                                     \
                    tci, "\n\ttest %s failed at line %d, %s != %s --> false", lcl_ti->ti_name, \
                    __LINE__, (reference), (actual));                                          \
                mtf_test_failure();                                                            \
            }                                                                                  \
            lcl_ti->ti_status = 0;                                                             \
            if (assert)                                                                        \
                return rc;                                                                     \
        } else {                                                                               \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                     \
        }                                                                                      \
    } while (0)

#define ___MTF_VERIFY_STRNE(reference, actual, rc) \
    ___MTF_VERIFY_INNER((strcmp((reference), (actual)) != 0), rc)

#define EXPECT_STRNE(reference, actual) EXPECT_STRNE_RET(reference, actual, )
#define ASSERT_STRNE(reference, actual) ASSERT_STRNE_RET(reference, actual, )
#define VERIFY_STRNE(reference, actual) VERIFY_STRNE_RET(reference, actual, )

#define EXPECT_STRNE_RET(reference, actual, rc) ___MTF_INNER_STRNE(0, (reference), (actual), rc)

#define ASSERT_STRNE_RET(reference, actual, rc) ___MTF_INNER_STRNE(1, (reference), (actual), rc)

#define VERIFY_STRNE_RET(reference, actual, rc) ___MTF_VERIFY_STRNE((reference), (actual), rc)

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_FLOAT_EQ(assert, reference, actual, rc)                                    \
    do {                                                                                        \
        struct mtf_test_coll_info *tci = lcl_ti->ti_coll;                                       \
        int res = ___mtf_almost_equal_ulps_and_abs(reference, actual, 0.00001, 4);              \
                                                                                                \
        tci = tci;                                                                              \
        if (mtf_verify_flag || !res) {                                                          \
            if (!mtf_verify_flag) {                                                             \
                mtf_print(                                                                      \
                    tci, "%s:%d: Failure %s == %s\n", __FILE__, __LINE__, #reference, #actual); \
                mtf_print(tci, "\t%g == %g --> false\n", (reference), (actual));                \
                mtf_test_failure();                                                             \
            }                                                                                   \
            lcl_ti->ti_status = 0;                                                              \
            if (assert)                                                                         \
                return rc;                                                                      \
        } else {                                                                                \
            lcl_ti->ti_status = lcl_ti->ti_status ? 1 : 0;                                      \
        }                                                                                       \
    } while (0)

#define ___MTF_VERIFY_FLOAT_EQ(reference, actual, rc)                              \
    do {                                                                           \
        int res = ___mtf_almost_equal_ulps_and_abs(reference, actual, 0.00001, 4); \
                                                                                   \
        ___MTF_VERIFY_INNER((res), rc)                                             \
    } while (0)

#define EXPECT_FLOAT_EQ(reference, actual) EXPECT_FLOAT_EQ_RET(reference, actual, )
#define ASSERT_FLOAT_EQ(reference, actual) ASSERT_FLOAT_EQ_RET(reference, actual, )
#define VERIFY_FLOAT_EQ(reference, actual) VERIFY_FLOAT_EQ_RET(reference, actual, )

#define EXPECT_FLOAT_EQ_RET(reference, actual, rc) \
    ___MTF_INNER_FLOAT_EQ(0, (reference), (actual), rc)

#define ASSERT_FLOAT_EQ_RET(reference, actual, rc) \
    ___MTF_INNER_FLOAT_EQ(1, (reference), (actual), rc)

#define VERIFY_FLOAT_EQ_RET(reference, actual, rc) ___MTF_VERIFY_FLOAT_EQ((reference), (actual), rc)

#endif /* HSE_UTEST_CONDITIONS_H */
