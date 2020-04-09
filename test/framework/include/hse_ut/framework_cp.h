/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015 Micron Technology, Inc. All rights reserved.
 */

#ifndef HSE_UTEST_FRAMEWORK_CP_H
#define HSE_UTEST_FRAMEWORK_CP_H

/*
 * !!! WARNING !!!
 *
 * This file is generated from the Python script "hse_test_framework_cp.py".
 * If you think you want to change this file, change the script and regenerate
 * this file from the updated script.
 */

/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP1(coll_name, test_name, pre_hook, post_hook, st0, vt0, v0) \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                       \
    {                                                                                          \
                                                                                               \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                       \
                                                                                               \
        ___MTF_CALL_GENERATOR(v0)                                                              \
                                                                                               \
    early_return_check:                                                                        \
        if (!lcl_ti->ti_status) {                                                              \
            return;                                                                            \
        }                                                                                      \
                                                                                               \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                            \
            v0 = ___mtf_##v0##_values[index0];

#define MTF_DEFINE_UTEST_CP1(coll_name, test_name, st0, vt0, v0) \
    ___MTF_INNER_DEFINE_UTEST_CP1(coll_name, test_name, 0, 0, st0, vt0, v0)

#define MTF_DEFINE_UTEST_CP1_PRE(coll_name, test_name, pre_hook, st0, vt0, v0) \
    ___MTF_INNER_DEFINE_UTEST_CP1(coll_name, test_name, pre_hook, 0, st0, vt0, v0)

#define MTF_DEFINE_UTEST_CP1_POST(coll_name, test_name, post_hook, st0, vt0, v0) \
    ___MTF_INNER_DEFINE_UTEST_CP1(coll_name, test_name, 0, post_hook, st0, vt0, v0)

#define MTF_DEFINE_UTEST_CP1_PREPOST(coll_name, test_name, pre_hook, post_hook, st0, vt0, v0) \
    ___MTF_INNER_DEFINE_UTEST_CP1(coll_name, test_name, pre_hook, post_hook, st0, vt0, v0)

#define MTF_END_CP1 \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP2(                                     \
    coll_name, test_name, pre_hook, post_hook, st0, vt0, v0, st1, vt1, v1) \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)   \
    {                                                                      \
                                                                           \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                   \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                   \
                                                                           \
        ___MTF_CALL_GENERATOR(v0)                                          \
        ___MTF_CALL_GENERATOR(v1)                                          \
                                                                           \
    early_return_check:                                                    \
        if (!lcl_ti->ti_status) {                                          \
            return;                                                        \
        }                                                                  \
                                                                           \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {        \
            v0 = ___mtf_##v0##_values[index0];                             \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {    \
                v1 = ___mtf_##v1##_values[index1];

#define MTF_DEFINE_UTEST_CP2(coll_name, test_name, st0, vt0, v0, st1, vt1, v1) \
    ___MTF_INNER_DEFINE_UTEST_CP2(coll_name, test_name, 0, 0, st0, vt0, v0, st1, vt1, v1)

#define MTF_DEFINE_UTEST_CP2_PRE(coll_name, test_name, pre_hook, st0, vt0, v0, st1, vt1, v1) \
    ___MTF_INNER_DEFINE_UTEST_CP2(coll_name, test_name, pre_hook, 0, st0, vt0, v0, st1, vt1, v1)

#define MTF_DEFINE_UTEST_CP2_POST(coll_name, test_name, post_hook, st0, vt0, v0, st1, vt1, v1) \
    ___MTF_INNER_DEFINE_UTEST_CP2(coll_name, test_name, 0, post_hook, st0, vt0, v0, st1, vt1, v1)

#define MTF_DEFINE_UTEST_CP2_PREPOST(                                      \
    coll_name, test_name, pre_hook, post_hook, st0, vt0, v0, st1, vt1, v1) \
    ___MTF_INNER_DEFINE_UTEST_CP2(                                         \
        coll_name, test_name, pre_hook, post_hook, st0, vt0, v0, st1, vt1, v1)

#define MTF_END_CP2 \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP3(                                                   \
    coll_name, test_name, pre_hook, post_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2) \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                 \
    {                                                                                    \
                                                                                         \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                 \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                                 \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                                 \
                                                                                         \
        ___MTF_CALL_GENERATOR(v0)                                                        \
        ___MTF_CALL_GENERATOR(v1)                                                        \
        ___MTF_CALL_GENERATOR(v2)                                                        \
                                                                                         \
    early_return_check:                                                                  \
        if (!lcl_ti->ti_status) {                                                        \
            return;                                                                      \
        }                                                                                \
                                                                                         \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                      \
            v0 = ___mtf_##v0##_values[index0];                                           \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {                  \
                v1 = ___mtf_##v1##_values[index1];                                       \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {              \
                    v2 = ___mtf_##v2##_values[index2];

#define MTF_DEFINE_UTEST_CP3(coll_name, test_name, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2) \
    ___MTF_INNER_DEFINE_UTEST_CP3(                                                           \
        coll_name, test_name, 0, 0, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2)

#define MTF_DEFINE_UTEST_CP3_PRE(                                             \
    coll_name, test_name, pre_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2) \
    ___MTF_INNER_DEFINE_UTEST_CP3(                                            \
        coll_name, test_name, pre_hook, 0, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2)

#define MTF_DEFINE_UTEST_CP3_POST(                                             \
    coll_name, test_name, post_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2) \
    ___MTF_INNER_DEFINE_UTEST_CP3(                                             \
        coll_name, test_name, 0, post_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2)

#define MTF_DEFINE_UTEST_CP3_PREPOST(                                                    \
    coll_name, test_name, pre_hook, post_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2) \
    ___MTF_INNER_DEFINE_UTEST_CP3(                                                       \
        coll_name, test_name, pre_hook, post_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2)

#define MTF_END_CP3 \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP4(                                          \
    coll_name,                                                                  \
    test_name,                                                                  \
    pre_hook,                                                                   \
    post_hook,                                                                  \
    st0,                                                                        \
    vt0,                                                                        \
    v0,                                                                         \
    st1,                                                                        \
    vt1,                                                                        \
    v1,                                                                         \
    st2,                                                                        \
    vt2,                                                                        \
    v2,                                                                         \
    st3,                                                                        \
    vt3,                                                                        \
    v3)                                                                         \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)        \
    {                                                                           \
                                                                                \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                        \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                        \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                        \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                        \
                                                                                \
        ___MTF_CALL_GENERATOR(v0)                                               \
        ___MTF_CALL_GENERATOR(v1)                                               \
        ___MTF_CALL_GENERATOR(v2)                                               \
        ___MTF_CALL_GENERATOR(v3)                                               \
                                                                                \
    early_return_check:                                                         \
        if (!lcl_ti->ti_status) {                                               \
            return;                                                             \
        }                                                                       \
                                                                                \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {             \
            v0 = ___mtf_##v0##_values[index0];                                  \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {         \
                v1 = ___mtf_##v1##_values[index1];                              \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {     \
                    v2 = ___mtf_##v2##_values[index2];                          \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) { \
                        v3 = ___mtf_##v3##_values[index3];

#define MTF_DEFINE_UTEST_CP4(                                                     \
    coll_name, test_name, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2, st3, vt3, v3) \
    ___MTF_INNER_DEFINE_UTEST_CP4(                                                \
        coll_name, test_name, 0, 0, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2, st3, vt3, v3)

#define MTF_DEFINE_UTEST_CP4_PRE(                                                           \
    coll_name, test_name, pre_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2, st3, vt3, v3) \
    ___MTF_INNER_DEFINE_UTEST_CP4(                                                          \
        coll_name, test_name, pre_hook, 0, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2, st3, vt3, v3)

#define MTF_DEFINE_UTEST_CP4_POST(                                                           \
    coll_name, test_name, post_hook, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2, st3, vt3, v3) \
    ___MTF_INNER_DEFINE_UTEST_CP4(                                                           \
        coll_name,                                                                           \
        test_name,                                                                           \
        0,                                                                                   \
        post_hook,                                                                           \
        st0,                                                                                 \
        vt0,                                                                                 \
        v0,                                                                                  \
        st1,                                                                                 \
        vt1,                                                                                 \
        v1,                                                                                  \
        st2,                                                                                 \
        vt2,                                                                                 \
        v2,                                                                                  \
        st3,                                                                                 \
        vt3,                                                                                 \
        v3)

#define MTF_DEFINE_UTEST_CP4_PREPOST( \
    coll_name,                        \
    test_name,                        \
    pre_hook,                         \
    post_hook,                        \
    st0,                              \
    vt0,                              \
    v0,                               \
    st1,                              \
    vt1,                              \
    v1,                               \
    st2,                              \
    vt2,                              \
    v2,                               \
    st3,                              \
    vt3,                              \
    v3)                               \
    ___MTF_INNER_DEFINE_UTEST_CP4(    \
        coll_name,                    \
        test_name,                    \
        pre_hook,                     \
        post_hook,                    \
        st0,                          \
        vt0,                          \
        v0,                           \
        st1,                          \
        vt1,                          \
        v1,                           \
        st2,                          \
        vt2,                          \
        v2,                           \
        st3,                          \
        vt3,                          \
        v3)

#define MTF_END_CP4 \
    }               \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP5(                                              \
    coll_name,                                                                      \
    test_name,                                                                      \
    pre_hook,                                                                       \
    post_hook,                                                                      \
    st0,                                                                            \
    vt0,                                                                            \
    v0,                                                                             \
    st1,                                                                            \
    vt1,                                                                            \
    v1,                                                                             \
    st2,                                                                            \
    vt2,                                                                            \
    v2,                                                                             \
    st3,                                                                            \
    vt3,                                                                            \
    v3,                                                                             \
    st4,                                                                            \
    vt4,                                                                            \
    v4)                                                                             \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)            \
    {                                                                               \
                                                                                    \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                            \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                            \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                            \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                            \
        ___MTF_VALUE_DECLARE(4, vt4, v4)                                            \
                                                                                    \
        ___MTF_CALL_GENERATOR(v0)                                                   \
        ___MTF_CALL_GENERATOR(v1)                                                   \
        ___MTF_CALL_GENERATOR(v2)                                                   \
        ___MTF_CALL_GENERATOR(v3)                                                   \
        ___MTF_CALL_GENERATOR(v4)                                                   \
                                                                                    \
    early_return_check:                                                             \
        if (!lcl_ti->ti_status) {                                                   \
            return;                                                                 \
        }                                                                           \
                                                                                    \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                 \
            v0 = ___mtf_##v0##_values[index0];                                      \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {             \
                v1 = ___mtf_##v1##_values[index1];                                  \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {         \
                    v2 = ___mtf_##v2##_values[index2];                              \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) {     \
                        v3 = ___mtf_##v3##_values[index3];                          \
                        for (index4 = 0; index4 < ___mtf_##v4##_length; ++index4) { \
                            v4 = ___mtf_##v4##_values[index4];

#define MTF_DEFINE_UTEST_CP5(                                                                   \
    coll_name, test_name, st0, vt0, v0, st1, vt1, v1, st2, vt2, v2, st3, vt3, v3, st4, vt4, v4) \
    ___MTF_INNER_DEFINE_UTEST_CP5(                                                              \
        coll_name,                                                                              \
        test_name,                                                                              \
        0,                                                                                      \
        0,                                                                                      \
        st0,                                                                                    \
        vt0,                                                                                    \
        v0,                                                                                     \
        st1,                                                                                    \
        vt1,                                                                                    \
        v1,                                                                                     \
        st2,                                                                                    \
        vt2,                                                                                    \
        v2,                                                                                     \
        st3,                                                                                    \
        vt3,                                                                                    \
        v3,                                                                                     \
        st4,                                                                                    \
        vt4,                                                                                    \
        v4)

#define MTF_DEFINE_UTEST_CP5_PRE(  \
    coll_name,                     \
    test_name,                     \
    pre_hook,                      \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4)                            \
    ___MTF_INNER_DEFINE_UTEST_CP5( \
        coll_name,                 \
        test_name,                 \
        pre_hook,                  \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4)

#define MTF_DEFINE_UTEST_CP5_POST( \
    coll_name,                     \
    test_name,                     \
    post_hook,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4)                            \
    ___MTF_INNER_DEFINE_UTEST_CP5( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        post_hook,                 \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4)

#define MTF_DEFINE_UTEST_CP5_PREPOST( \
    coll_name,                        \
    test_name,                        \
    pre_hook,                         \
    post_hook,                        \
    st0,                              \
    vt0,                              \
    v0,                               \
    st1,                              \
    vt1,                              \
    v1,                               \
    st2,                              \
    vt2,                              \
    v2,                               \
    st3,                              \
    vt3,                              \
    v3,                               \
    st4,                              \
    vt4,                              \
    v4)                               \
    ___MTF_INNER_DEFINE_UTEST_CP5(    \
        coll_name,                    \
        test_name,                    \
        pre_hook,                     \
        post_hook,                    \
        st0,                          \
        vt0,                          \
        v0,                           \
        st1,                          \
        vt1,                          \
        v1,                           \
        st2,                          \
        vt2,                          \
        v2,                           \
        st3,                          \
        vt3,                          \
        v3,                           \
        st4,                          \
        vt4,                          \
        v4)

#define MTF_END_CP5 \
    }               \
    }               \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP6(                                                  \
    coll_name,                                                                          \
    test_name,                                                                          \
    pre_hook,                                                                           \
    post_hook,                                                                          \
    st0,                                                                                \
    vt0,                                                                                \
    v0,                                                                                 \
    st1,                                                                                \
    vt1,                                                                                \
    v1,                                                                                 \
    st2,                                                                                \
    vt2,                                                                                \
    v2,                                                                                 \
    st3,                                                                                \
    vt3,                                                                                \
    v3,                                                                                 \
    st4,                                                                                \
    vt4,                                                                                \
    v4,                                                                                 \
    st5,                                                                                \
    vt5,                                                                                \
    v5)                                                                                 \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                \
    {                                                                                   \
                                                                                        \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                                \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                                \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                                \
        ___MTF_VALUE_DECLARE(4, vt4, v4)                                                \
        ___MTF_VALUE_DECLARE(5, vt5, v5)                                                \
                                                                                        \
        ___MTF_CALL_GENERATOR(v0)                                                       \
        ___MTF_CALL_GENERATOR(v1)                                                       \
        ___MTF_CALL_GENERATOR(v2)                                                       \
        ___MTF_CALL_GENERATOR(v3)                                                       \
        ___MTF_CALL_GENERATOR(v4)                                                       \
        ___MTF_CALL_GENERATOR(v5)                                                       \
                                                                                        \
    early_return_check:                                                                 \
        if (!lcl_ti->ti_status) {                                                       \
            return;                                                                     \
        }                                                                               \
                                                                                        \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                     \
            v0 = ___mtf_##v0##_values[index0];                                          \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {                 \
                v1 = ___mtf_##v1##_values[index1];                                      \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {             \
                    v2 = ___mtf_##v2##_values[index2];                                  \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) {         \
                        v3 = ___mtf_##v3##_values[index3];                              \
                        for (index4 = 0; index4 < ___mtf_##v4##_length; ++index4) {     \
                            v4 = ___mtf_##v4##_values[index4];                          \
                            for (index5 = 0; index5 < ___mtf_##v5##_length; ++index5) { \
                                v5 = ___mtf_##v5##_values[index5];

#define MTF_DEFINE_UTEST_CP6(      \
    coll_name,                     \
    test_name,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5)                            \
    ___MTF_INNER_DEFINE_UTEST_CP6( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5)

#define MTF_DEFINE_UTEST_CP6_PRE(  \
    coll_name,                     \
    test_name,                     \
    pre_hook,                      \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5)                            \
    ___MTF_INNER_DEFINE_UTEST_CP6( \
        coll_name,                 \
        test_name,                 \
        pre_hook,                  \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5)

#define MTF_DEFINE_UTEST_CP6_POST( \
    coll_name,                     \
    test_name,                     \
    post_hook,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5)                            \
    ___MTF_INNER_DEFINE_UTEST_CP6( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        post_hook,                 \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5)

#define MTF_DEFINE_UTEST_CP6_PREPOST( \
    coll_name,                        \
    test_name,                        \
    pre_hook,                         \
    post_hook,                        \
    st0,                              \
    vt0,                              \
    v0,                               \
    st1,                              \
    vt1,                              \
    v1,                               \
    st2,                              \
    vt2,                              \
    v2,                               \
    st3,                              \
    vt3,                              \
    v3,                               \
    st4,                              \
    vt4,                              \
    v4,                               \
    st5,                              \
    vt5,                              \
    v5)                               \
    ___MTF_INNER_DEFINE_UTEST_CP6(    \
        coll_name,                    \
        test_name,                    \
        pre_hook,                     \
        post_hook,                    \
        st0,                          \
        vt0,                          \
        v0,                           \
        st1,                          \
        vt1,                          \
        v1,                           \
        st2,                          \
        vt2,                          \
        v2,                           \
        st3,                          \
        vt3,                          \
        v3,                           \
        st4,                          \
        vt4,                          \
        v4,                           \
        st5,                          \
        vt5,                          \
        v5)

#define MTF_END_CP6 \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP7(                                                      \
    coll_name,                                                                              \
    test_name,                                                                              \
    pre_hook,                                                                               \
    post_hook,                                                                              \
    st0,                                                                                    \
    vt0,                                                                                    \
    v0,                                                                                     \
    st1,                                                                                    \
    vt1,                                                                                    \
    v1,                                                                                     \
    st2,                                                                                    \
    vt2,                                                                                    \
    v2,                                                                                     \
    st3,                                                                                    \
    vt3,                                                                                    \
    v3,                                                                                     \
    st4,                                                                                    \
    vt4,                                                                                    \
    v4,                                                                                     \
    st5,                                                                                    \
    vt5,                                                                                    \
    v5,                                                                                     \
    st6,                                                                                    \
    vt6,                                                                                    \
    v6)                                                                                     \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                    \
    {                                                                                       \
                                                                                            \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                    \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                                    \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                                    \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                                    \
        ___MTF_VALUE_DECLARE(4, vt4, v4)                                                    \
        ___MTF_VALUE_DECLARE(5, vt5, v5)                                                    \
        ___MTF_VALUE_DECLARE(6, vt6, v6)                                                    \
                                                                                            \
        ___MTF_CALL_GENERATOR(v0)                                                           \
        ___MTF_CALL_GENERATOR(v1)                                                           \
        ___MTF_CALL_GENERATOR(v2)                                                           \
        ___MTF_CALL_GENERATOR(v3)                                                           \
        ___MTF_CALL_GENERATOR(v4)                                                           \
        ___MTF_CALL_GENERATOR(v5)                                                           \
        ___MTF_CALL_GENERATOR(v6)                                                           \
                                                                                            \
    early_return_check:                                                                     \
        if (!lcl_ti->ti_status) {                                                           \
            return;                                                                         \
        }                                                                                   \
                                                                                            \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                         \
            v0 = ___mtf_##v0##_values[index0];                                              \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {                     \
                v1 = ___mtf_##v1##_values[index1];                                          \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {                 \
                    v2 = ___mtf_##v2##_values[index2];                                      \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) {             \
                        v3 = ___mtf_##v3##_values[index3];                                  \
                        for (index4 = 0; index4 < ___mtf_##v4##_length; ++index4) {         \
                            v4 = ___mtf_##v4##_values[index4];                              \
                            for (index5 = 0; index5 < ___mtf_##v5##_length; ++index5) {     \
                                v5 = ___mtf_##v5##_values[index5];                          \
                                for (index6 = 0; index6 < ___mtf_##v6##_length; ++index6) { \
                                    v6 = ___mtf_##v6##_values[index6];

#define MTF_DEFINE_UTEST_CP7(      \
    coll_name,                     \
    test_name,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6)                            \
    ___MTF_INNER_DEFINE_UTEST_CP7( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6)

#define MTF_DEFINE_UTEST_CP7_PRE(  \
    coll_name,                     \
    test_name,                     \
    pre_hook,                      \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6)                            \
    ___MTF_INNER_DEFINE_UTEST_CP7( \
        coll_name,                 \
        test_name,                 \
        pre_hook,                  \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6)

#define MTF_DEFINE_UTEST_CP7_POST( \
    coll_name,                     \
    test_name,                     \
    post_hook,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6)                            \
    ___MTF_INNER_DEFINE_UTEST_CP7( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        post_hook,                 \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6)

#define MTF_DEFINE_UTEST_CP7_PREPOST( \
    coll_name,                        \
    test_name,                        \
    pre_hook,                         \
    post_hook,                        \
    st0,                              \
    vt0,                              \
    v0,                               \
    st1,                              \
    vt1,                              \
    v1,                               \
    st2,                              \
    vt2,                              \
    v2,                               \
    st3,                              \
    vt3,                              \
    v3,                               \
    st4,                              \
    vt4,                              \
    v4,                               \
    st5,                              \
    vt5,                              \
    v5,                               \
    st6,                              \
    vt6,                              \
    v6)                               \
    ___MTF_INNER_DEFINE_UTEST_CP7(    \
        coll_name,                    \
        test_name,                    \
        pre_hook,                     \
        post_hook,                    \
        st0,                          \
        vt0,                          \
        v0,                           \
        st1,                          \
        vt1,                          \
        v1,                           \
        st2,                          \
        vt2,                          \
        v2,                           \
        st3,                          \
        vt3,                          \
        v3,                           \
        st4,                          \
        vt4,                          \
        v4,                           \
        st5,                          \
        vt5,                          \
        v5,                           \
        st6,                          \
        vt6,                          \
        v6)

#define MTF_END_CP7 \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP8(                                                          \
    coll_name,                                                                                  \
    test_name,                                                                                  \
    pre_hook,                                                                                   \
    post_hook,                                                                                  \
    st0,                                                                                        \
    vt0,                                                                                        \
    v0,                                                                                         \
    st1,                                                                                        \
    vt1,                                                                                        \
    v1,                                                                                         \
    st2,                                                                                        \
    vt2,                                                                                        \
    v2,                                                                                         \
    st3,                                                                                        \
    vt3,                                                                                        \
    v3,                                                                                         \
    st4,                                                                                        \
    vt4,                                                                                        \
    v4,                                                                                         \
    st5,                                                                                        \
    vt5,                                                                                        \
    v5,                                                                                         \
    st6,                                                                                        \
    vt6,                                                                                        \
    v6,                                                                                         \
    st7,                                                                                        \
    vt7,                                                                                        \
    v7)                                                                                         \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                        \
    {                                                                                           \
                                                                                                \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                        \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                                        \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                                        \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                                        \
        ___MTF_VALUE_DECLARE(4, vt4, v4)                                                        \
        ___MTF_VALUE_DECLARE(5, vt5, v5)                                                        \
        ___MTF_VALUE_DECLARE(6, vt6, v6)                                                        \
        ___MTF_VALUE_DECLARE(7, vt7, v7)                                                        \
                                                                                                \
        ___MTF_CALL_GENERATOR(v0)                                                               \
        ___MTF_CALL_GENERATOR(v1)                                                               \
        ___MTF_CALL_GENERATOR(v2)                                                               \
        ___MTF_CALL_GENERATOR(v3)                                                               \
        ___MTF_CALL_GENERATOR(v4)                                                               \
        ___MTF_CALL_GENERATOR(v5)                                                               \
        ___MTF_CALL_GENERATOR(v6)                                                               \
        ___MTF_CALL_GENERATOR(v7)                                                               \
                                                                                                \
    early_return_check:                                                                         \
        if (!lcl_ti->ti_status) {                                                               \
            return;                                                                             \
        }                                                                                       \
                                                                                                \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                             \
            v0 = ___mtf_##v0##_values[index0];                                                  \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {                         \
                v1 = ___mtf_##v1##_values[index1];                                              \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {                     \
                    v2 = ___mtf_##v2##_values[index2];                                          \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) {                 \
                        v3 = ___mtf_##v3##_values[index3];                                      \
                        for (index4 = 0; index4 < ___mtf_##v4##_length; ++index4) {             \
                            v4 = ___mtf_##v4##_values[index4];                                  \
                            for (index5 = 0; index5 < ___mtf_##v5##_length; ++index5) {         \
                                v5 = ___mtf_##v5##_values[index5];                              \
                                for (index6 = 0; index6 < ___mtf_##v6##_length; ++index6) {     \
                                    v6 = ___mtf_##v6##_values[index6];                          \
                                    for (index7 = 0; index7 < ___mtf_##v7##_length; ++index7) { \
                                        v7 = ___mtf_##v7##_values[index7];

#define MTF_DEFINE_UTEST_CP8(      \
    coll_name,                     \
    test_name,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6,                            \
    st7,                           \
    vt7,                           \
    v7)                            \
    ___MTF_INNER_DEFINE_UTEST_CP8( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6,                        \
        st7,                       \
        vt7,                       \
        v7)

#define MTF_DEFINE_UTEST_CP8_PRE(  \
    coll_name,                     \
    test_name,                     \
    pre_hook,                      \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6,                            \
    st7,                           \
    vt7,                           \
    v7)                            \
    ___MTF_INNER_DEFINE_UTEST_CP8( \
        coll_name,                 \
        test_name,                 \
        pre_hook,                  \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6,                        \
        st7,                       \
        vt7,                       \
        v7)

#define MTF_DEFINE_UTEST_CP8_POST( \
    coll_name,                     \
    test_name,                     \
    post_hook,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6,                            \
    st7,                           \
    vt7,                           \
    v7)                            \
    ___MTF_INNER_DEFINE_UTEST_CP8( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        post_hook,                 \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6,                        \
        st7,                       \
        vt7,                       \
        v7)

#define MTF_DEFINE_UTEST_CP8_PREPOST( \
    coll_name,                        \
    test_name,                        \
    pre_hook,                         \
    post_hook,                        \
    st0,                              \
    vt0,                              \
    v0,                               \
    st1,                              \
    vt1,                              \
    v1,                               \
    st2,                              \
    vt2,                              \
    v2,                               \
    st3,                              \
    vt3,                              \
    v3,                               \
    st4,                              \
    vt4,                              \
    v4,                               \
    st5,                              \
    vt5,                              \
    v5,                               \
    st6,                              \
    vt6,                              \
    v6,                               \
    st7,                              \
    vt7,                              \
    v7)                               \
    ___MTF_INNER_DEFINE_UTEST_CP8(    \
        coll_name,                    \
        test_name,                    \
        pre_hook,                     \
        post_hook,                    \
        st0,                          \
        vt0,                          \
        v0,                           \
        st1,                          \
        vt1,                          \
        v1,                           \
        st2,                          \
        vt2,                          \
        v2,                           \
        st3,                          \
        vt3,                          \
        v3,                           \
        st4,                          \
        vt4,                          \
        v4,                           \
        st5,                          \
        vt5,                          \
        v5,                           \
        st6,                          \
        vt6,                          \
        v6,                           \
        st7,                          \
        vt7,                          \
        v7)

#define MTF_END_CP8 \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP9(                                                          \
    coll_name,                                                                                  \
    test_name,                                                                                  \
    pre_hook,                                                                                   \
    post_hook,                                                                                  \
    st0,                                                                                        \
    vt0,                                                                                        \
    v0,                                                                                         \
    st1,                                                                                        \
    vt1,                                                                                        \
    v1,                                                                                         \
    st2,                                                                                        \
    vt2,                                                                                        \
    v2,                                                                                         \
    st3,                                                                                        \
    vt3,                                                                                        \
    v3,                                                                                         \
    st4,                                                                                        \
    vt4,                                                                                        \
    v4,                                                                                         \
    st5,                                                                                        \
    vt5,                                                                                        \
    v5,                                                                                         \
    st6,                                                                                        \
    vt6,                                                                                        \
    v6,                                                                                         \
    st7,                                                                                        \
    vt7,                                                                                        \
    v7,                                                                                         \
    st8,                                                                                        \
    vt8,                                                                                        \
    v8)                                                                                         \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                        \
    {                                                                                           \
                                                                                                \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                        \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                                        \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                                        \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                                        \
        ___MTF_VALUE_DECLARE(4, vt4, v4)                                                        \
        ___MTF_VALUE_DECLARE(5, vt5, v5)                                                        \
        ___MTF_VALUE_DECLARE(6, vt6, v6)                                                        \
        ___MTF_VALUE_DECLARE(7, vt7, v7)                                                        \
        ___MTF_VALUE_DECLARE(8, vt8, v8)                                                        \
                                                                                                \
        ___MTF_CALL_GENERATOR(v0)                                                               \
        ___MTF_CALL_GENERATOR(v1)                                                               \
        ___MTF_CALL_GENERATOR(v2)                                                               \
        ___MTF_CALL_GENERATOR(v3)                                                               \
        ___MTF_CALL_GENERATOR(v4)                                                               \
        ___MTF_CALL_GENERATOR(v5)                                                               \
        ___MTF_CALL_GENERATOR(v6)                                                               \
        ___MTF_CALL_GENERATOR(v7)                                                               \
        ___MTF_CALL_GENERATOR(v8)                                                               \
                                                                                                \
    early_return_check:                                                                         \
        if (!lcl_ti->ti_status) {                                                               \
            return;                                                                             \
        }                                                                                       \
                                                                                                \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                             \
            v0 = ___mtf_##v0##_values[index0];                                                  \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {                         \
                v1 = ___mtf_##v1##_values[index1];                                              \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {                     \
                    v2 = ___mtf_##v2##_values[index2];                                          \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) {                 \
                        v3 = ___mtf_##v3##_values[index3];                                      \
                        for (index4 = 0; index4 < ___mtf_##v4##_length; ++index4) {             \
                            v4 = ___mtf_##v4##_values[index4];                                  \
                            for (index5 = 0; index5 < ___mtf_##v5##_length; ++index5) {         \
                                v5 = ___mtf_##v5##_values[index5];                              \
                                for (index6 = 0; index6 < ___mtf_##v6##_length; ++index6) {     \
                                    v6 = ___mtf_##v6##_values[index6];                          \
                                    for (index7 = 0; index7 < ___mtf_##v7##_length; ++index7) { \
                                        v7 = ___mtf_##v7##_values[index7];                      \
                                        for (index8 = 0; index8 < ___mtf_##v8##_length;         \
                                             ++index8) {                                        \
                                            v8 = ___mtf_##v8##_values[index8];

#define MTF_DEFINE_UTEST_CP9(      \
    coll_name,                     \
    test_name,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6,                            \
    st7,                           \
    vt7,                           \
    v7,                            \
    st8,                           \
    vt8,                           \
    v8)                            \
    ___MTF_INNER_DEFINE_UTEST_CP9( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6,                        \
        st7,                       \
        vt7,                       \
        v7,                        \
        st8,                       \
        vt8,                       \
        v8)

#define MTF_DEFINE_UTEST_CP9_PRE(  \
    coll_name,                     \
    test_name,                     \
    pre_hook,                      \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6,                            \
    st7,                           \
    vt7,                           \
    v7,                            \
    st8,                           \
    vt8,                           \
    v8)                            \
    ___MTF_INNER_DEFINE_UTEST_CP9( \
        coll_name,                 \
        test_name,                 \
        pre_hook,                  \
        0,                         \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6,                        \
        st7,                       \
        vt7,                       \
        v7,                        \
        st8,                       \
        vt8,                       \
        v8)

#define MTF_DEFINE_UTEST_CP9_POST( \
    coll_name,                     \
    test_name,                     \
    post_hook,                     \
    st0,                           \
    vt0,                           \
    v0,                            \
    st1,                           \
    vt1,                           \
    v1,                            \
    st2,                           \
    vt2,                           \
    v2,                            \
    st3,                           \
    vt3,                           \
    v3,                            \
    st4,                           \
    vt4,                           \
    v4,                            \
    st5,                           \
    vt5,                           \
    v5,                            \
    st6,                           \
    vt6,                           \
    v6,                            \
    st7,                           \
    vt7,                           \
    v7,                            \
    st8,                           \
    vt8,                           \
    v8)                            \
    ___MTF_INNER_DEFINE_UTEST_CP9( \
        coll_name,                 \
        test_name,                 \
        0,                         \
        post_hook,                 \
        st0,                       \
        vt0,                       \
        v0,                        \
        st1,                       \
        vt1,                       \
        v1,                        \
        st2,                       \
        vt2,                       \
        v2,                        \
        st3,                       \
        vt3,                       \
        v3,                        \
        st4,                       \
        vt4,                       \
        v4,                        \
        st5,                       \
        vt5,                       \
        v5,                        \
        st6,                       \
        vt6,                       \
        v6,                        \
        st7,                       \
        vt7,                       \
        v7,                        \
        st8,                       \
        vt8,                       \
        v8)

#define MTF_DEFINE_UTEST_CP9_PREPOST( \
    coll_name,                        \
    test_name,                        \
    pre_hook,                         \
    post_hook,                        \
    st0,                              \
    vt0,                              \
    v0,                               \
    st1,                              \
    vt1,                              \
    v1,                               \
    st2,                              \
    vt2,                              \
    v2,                               \
    st3,                              \
    vt3,                              \
    v3,                               \
    st4,                              \
    vt4,                              \
    v4,                               \
    st5,                              \
    vt5,                              \
    v5,                               \
    st6,                              \
    vt6,                              \
    v6,                               \
    st7,                              \
    vt7,                              \
    v7,                               \
    st8,                              \
    vt8,                              \
    v8)                               \
    ___MTF_INNER_DEFINE_UTEST_CP9(    \
        coll_name,                    \
        test_name,                    \
        pre_hook,                     \
        post_hook,                    \
        st0,                          \
        vt0,                          \
        v0,                           \
        st1,                          \
        vt1,                          \
        v1,                           \
        st2,                          \
        vt2,                          \
        v2,                           \
        st3,                          \
        vt3,                          \
        v3,                           \
        st4,                          \
        vt4,                          \
        v4,                           \
        st5,                          \
        vt5,                          \
        v5,                           \
        st6,                          \
        vt6,                          \
        v6,                           \
        st7,                          \
        vt7,                          \
        v7,                           \
        st8,                          \
        vt8,                          \
        v8)

#define MTF_END_CP9 \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }               \
    }

/* ------------------------------------------------------------------------- */
/* ------------------------------------------------------------------------- */

#define ___MTF_INNER_DEFINE_UTEST_CP10(                                                         \
    coll_name,                                                                                  \
    test_name,                                                                                  \
    pre_hook,                                                                                   \
    post_hook,                                                                                  \
    st0,                                                                                        \
    vt0,                                                                                        \
    v0,                                                                                         \
    st1,                                                                                        \
    vt1,                                                                                        \
    v1,                                                                                         \
    st2,                                                                                        \
    vt2,                                                                                        \
    v2,                                                                                         \
    st3,                                                                                        \
    vt3,                                                                                        \
    v3,                                                                                         \
    st4,                                                                                        \
    vt4,                                                                                        \
    v4,                                                                                         \
    st5,                                                                                        \
    vt5,                                                                                        \
    v5,                                                                                         \
    st6,                                                                                        \
    vt6,                                                                                        \
    v6,                                                                                         \
    st7,                                                                                        \
    vt7,                                                                                        \
    v7,                                                                                         \
    st8,                                                                                        \
    vt8,                                                                                        \
    v8,                                                                                         \
    st9,                                                                                        \
    vt9,                                                                                        \
    v9)                                                                                         \
    ___MTF_INNER_DEFINE_UTEST(coll_name, test_name, pre_hook, post_hook)                        \
    {                                                                                           \
                                                                                                \
        ___MTF_VALUE_DECLARE(0, vt0, v0)                                                        \
        ___MTF_VALUE_DECLARE(1, vt1, v1)                                                        \
        ___MTF_VALUE_DECLARE(2, vt2, v2)                                                        \
        ___MTF_VALUE_DECLARE(3, vt3, v3)                                                        \
        ___MTF_VALUE_DECLARE(4, vt4, v4)                                                        \
        ___MTF_VALUE_DECLARE(5, vt5, v5)                                                        \
        ___MTF_VALUE_DECLARE(6, vt6, v6)                                                        \
        ___MTF_VALUE_DECLARE(7, vt7, v7)                                                        \
        ___MTF_VALUE_DECLARE(8, vt8, v8)                                                        \
        ___MTF_VALUE_DECLARE(9, vt9, v9)                                                        \
                                                                                                \
        ___MTF_CALL_GENERATOR(v0)                                                               \
        ___MTF_CALL_GENERATOR(v1)                                                               \
        ___MTF_CALL_GENERATOR(v2)                                                               \
        ___MTF_CALL_GENERATOR(v3)                                                               \
        ___MTF_CALL_GENERATOR(v4)                                                               \
        ___MTF_CALL_GENERATOR(v5)                                                               \
        ___MTF_CALL_GENERATOR(v6)                                                               \
        ___MTF_CALL_GENERATOR(v7)                                                               \
        ___MTF_CALL_GENERATOR(v8)                                                               \
        ___MTF_CALL_GENERATOR(v9)                                                               \
                                                                                                \
    early_return_check:                                                                         \
        if (!lcl_ti->ti_status) {                                                               \
            return;                                                                             \
        }                                                                                       \
                                                                                                \
        for (index0 = 0; index0 < ___mtf_##v0##_length; ++index0) {                             \
            v0 = ___mtf_##v0##_values[index0];                                                  \
            for (index1 = 0; index1 < ___mtf_##v1##_length; ++index1) {                         \
                v1 = ___mtf_##v1##_values[index1];                                              \
                for (index2 = 0; index2 < ___mtf_##v2##_length; ++index2) {                     \
                    v2 = ___mtf_##v2##_values[index2];                                          \
                    for (index3 = 0; index3 < ___mtf_##v3##_length; ++index3) {                 \
                        v3 = ___mtf_##v3##_values[index3];                                      \
                        for (index4 = 0; index4 < ___mtf_##v4##_length; ++index4) {             \
                            v4 = ___mtf_##v4##_values[index4];                                  \
                            for (index5 = 0; index5 < ___mtf_##v5##_length; ++index5) {         \
                                v5 = ___mtf_##v5##_values[index5];                              \
                                for (index6 = 0; index6 < ___mtf_##v6##_length; ++index6) {     \
                                    v6 = ___mtf_##v6##_values[index6];                          \
                                    for (index7 = 0; index7 < ___mtf_##v7##_length; ++index7) { \
                                        v7 = ___mtf_##v7##_values[index7];                      \
                                        for (index8 = 0; index8 < ___mtf_##v8##_length;         \
                                             ++index8) {                                        \
                                            v8 = ___mtf_##v8##_values[index8];                  \
                                            for (index9 = 0; index9 < ___mtf_##v9##_length;     \
                                                 ++index9) {                                    \
                                                v9 = ___mtf_##v9##_values[index9];

#define MTF_DEFINE_UTEST_CP10(      \
    coll_name,                      \
    test_name,                      \
    st0,                            \
    vt0,                            \
    v0,                             \
    st1,                            \
    vt1,                            \
    v1,                             \
    st2,                            \
    vt2,                            \
    v2,                             \
    st3,                            \
    vt3,                            \
    v3,                             \
    st4,                            \
    vt4,                            \
    v4,                             \
    st5,                            \
    vt5,                            \
    v5,                             \
    st6,                            \
    vt6,                            \
    v6,                             \
    st7,                            \
    vt7,                            \
    v7,                             \
    st8,                            \
    vt8,                            \
    v8,                             \
    st9,                            \
    vt9,                            \
    v9)                             \
    ___MTF_INNER_DEFINE_UTEST_CP10( \
        coll_name,                  \
        test_name,                  \
        0,                          \
        0,                          \
        st0,                        \
        vt0,                        \
        v0,                         \
        st1,                        \
        vt1,                        \
        v1,                         \
        st2,                        \
        vt2,                        \
        v2,                         \
        st3,                        \
        vt3,                        \
        v3,                         \
        st4,                        \
        vt4,                        \
        v4,                         \
        st5,                        \
        vt5,                        \
        v5,                         \
        st6,                        \
        vt6,                        \
        v6,                         \
        st7,                        \
        vt7,                        \
        v7,                         \
        st8,                        \
        vt8,                        \
        v8,                         \
        st9,                        \
        vt9,                        \
        v9)

#define MTF_DEFINE_UTEST_CP10_PRE(  \
    coll_name,                      \
    test_name,                      \
    pre_hook,                       \
    st0,                            \
    vt0,                            \
    v0,                             \
    st1,                            \
    vt1,                            \
    v1,                             \
    st2,                            \
    vt2,                            \
    v2,                             \
    st3,                            \
    vt3,                            \
    v3,                             \
    st4,                            \
    vt4,                            \
    v4,                             \
    st5,                            \
    vt5,                            \
    v5,                             \
    st6,                            \
    vt6,                            \
    v6,                             \
    st7,                            \
    vt7,                            \
    v7,                             \
    st8,                            \
    vt8,                            \
    v8,                             \
    st9,                            \
    vt9,                            \
    v9)                             \
    ___MTF_INNER_DEFINE_UTEST_CP10( \
        coll_name,                  \
        test_name,                  \
        pre_hook,                   \
        0,                          \
        st0,                        \
        vt0,                        \
        v0,                         \
        st1,                        \
        vt1,                        \
        v1,                         \
        st2,                        \
        vt2,                        \
        v2,                         \
        st3,                        \
        vt3,                        \
        v3,                         \
        st4,                        \
        vt4,                        \
        v4,                         \
        st5,                        \
        vt5,                        \
        v5,                         \
        st6,                        \
        vt6,                        \
        v6,                         \
        st7,                        \
        vt7,                        \
        v7,                         \
        st8,                        \
        vt8,                        \
        v8,                         \
        st9,                        \
        vt9,                        \
        v9)

#define MTF_DEFINE_UTEST_CP10_POST( \
    coll_name,                      \
    test_name,                      \
    post_hook,                      \
    st0,                            \
    vt0,                            \
    v0,                             \
    st1,                            \
    vt1,                            \
    v1,                             \
    st2,                            \
    vt2,                            \
    v2,                             \
    st3,                            \
    vt3,                            \
    v3,                             \
    st4,                            \
    vt4,                            \
    v4,                             \
    st5,                            \
    vt5,                            \
    v5,                             \
    st6,                            \
    vt6,                            \
    v6,                             \
    st7,                            \
    vt7,                            \
    v7,                             \
    st8,                            \
    vt8,                            \
    v8,                             \
    st9,                            \
    vt9,                            \
    v9)                             \
    ___MTF_INNER_DEFINE_UTEST_CP10( \
        coll_name,                  \
        test_name,                  \
        0,                          \
        post_hook,                  \
        st0,                        \
        vt0,                        \
        v0,                         \
        st1,                        \
        vt1,                        \
        v1,                         \
        st2,                        \
        vt2,                        \
        v2,                         \
        st3,                        \
        vt3,                        \
        v3,                         \
        st4,                        \
        vt4,                        \
        v4,                         \
        st5,                        \
        vt5,                        \
        v5,                         \
        st6,                        \
        vt6,                        \
        v6,                         \
        st7,                        \
        vt7,                        \
        v7,                         \
        st8,                        \
        vt8,                        \
        v8,                         \
        st9,                        \
        vt9,                        \
        v9)

#define MTF_DEFINE_UTEST_CP10_PREPOST( \
    coll_name,                         \
    test_name,                         \
    pre_hook,                          \
    post_hook,                         \
    st0,                               \
    vt0,                               \
    v0,                                \
    st1,                               \
    vt1,                               \
    v1,                                \
    st2,                               \
    vt2,                               \
    v2,                                \
    st3,                               \
    vt3,                               \
    v3,                                \
    st4,                               \
    vt4,                               \
    v4,                                \
    st5,                               \
    vt5,                               \
    v5,                                \
    st6,                               \
    vt6,                               \
    v6,                                \
    st7,                               \
    vt7,                               \
    v7,                                \
    st8,                               \
    vt8,                               \
    v8,                                \
    st9,                               \
    vt9,                               \
    v9)                                \
    ___MTF_INNER_DEFINE_UTEST_CP10(    \
        coll_name,                     \
        test_name,                     \
        pre_hook,                      \
        post_hook,                     \
        st0,                           \
        vt0,                           \
        v0,                            \
        st1,                           \
        vt1,                           \
        v1,                            \
        st2,                           \
        vt2,                           \
        v2,                            \
        st3,                           \
        vt3,                           \
        v3,                            \
        st4,                           \
        vt4,                           \
        v4,                            \
        st5,                           \
        vt5,                           \
        v5,                            \
        st6,                           \
        vt6,                           \
        v6,                            \
        st7,                           \
        vt7,                           \
        v7,                            \
        st8,                           \
        vt8,                           \
        v8,                            \
        st9,                           \
        vt9,                           \
        v9)

#define MTF_END_CP10 \
    }                \
    }                \
    }                \
    }                \
    }                \
    }                \
    }                \
    }                \
    }                \
    }                \
    }

/* ------------------------------------------------------------------------- */
#endif
