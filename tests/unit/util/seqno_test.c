/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_ut/framework.h>
#include <hse_util/hse_err.h>
#include <hse_util/seqno.h>

MTF_BEGIN_UTEST_COLLECTION(seqno_test)

MTF_DEFINE_UTEST(seqno_test, seqno_check_pred)
{
    uintptr_t *seqno;

    seqno = (uintptr_t *)((uintptr_t)-1L - 1);
    ASSERT_TRUE(HSE_SQNREF_UNDEF_P(seqno));
    ASSERT_FALSE(HSE_SQNREF_ORDNL_P(seqno));

    seqno = (uintptr_t *)(1);
    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
    ASSERT_TRUE(HSE_SQNREF_ORDNL_P(seqno));

    seqno = (uintptr_t *)(13);
    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
    ASSERT_TRUE(HSE_SQNREF_ORDNL_P(seqno));

    seqno = (uintptr_t *)(102939917);
    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
    ASSERT_TRUE(HSE_SQNREF_ORDNL_P(seqno));
}

MTF_DEFINE_UTEST(seqno_test, seqno_check_ord)
{
    uintptr_t            seqno;
    uintptr_t            ord, chk;
    enum hse_seqno_state state;

    for (ord = 0; ord < 100; ++ord) {
        seqno = HSE_ORDNL_TO_SQNREF(ord);
        ASSERT_TRUE(HSE_SQNREF_ORDNL_P(seqno));
        ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
        state = seqnoref_to_seqno(seqno, &chk);
        ASSERT_EQ(HSE_SQNREF_STATE_DEFINED, state);
        ASSERT_EQ(ord, chk);
    }
}

MTF_DEFINE_UTEST(seqno_test, seqno_check_ref)
{
    uintptr_t            seqno;
    uintptr_t            ref;
    uintptr_t            ord, chk = 0;
    enum hse_seqno_state state;

    for (ord = 0; ord < 100; ++ord) {
        ref = HSE_ORDNL_TO_SQNREF(ord);
        seqno = HSE_REF_TO_SQNREF(&ref);
        ASSERT_FALSE(HSE_SQNREF_ORDNL_P(seqno));
        ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
        state = seqnoref_to_seqno(seqno, &chk);
        ASSERT_EQ(ord, chk);
    }

    ref = HSE_SQNREF_UNDEFINED;
    seqno = HSE_REF_TO_SQNREF(&ref);
    ASSERT_FALSE(HSE_SQNREF_ORDNL_P(seqno));
    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
    state = seqnoref_to_seqno(seqno, &chk);
    ASSERT_EQ(HSE_SQNREF_STATE_UNDEFINED, state);

    ref = HSE_SQNREF_ABORTED;
    seqno = HSE_REF_TO_SQNREF(&ref);
    ASSERT_FALSE(HSE_SQNREF_ORDNL_P(seqno));
    ASSERT_FALSE(HSE_SQNREF_UNDEF_P(seqno));
    state = seqnoref_to_seqno(seqno, &chk);
}

MTF_DEFINE_UTEST(seqno_test, seqno_test_seqnoref_ext_diff)
{
    uintptr_t ref;
    u64       ord;
    u64       diff;

    ref = HSE_ORDNL_TO_SQNREF(50);

    for (ord = 0; ord < 100; ++ord) {
        if (ord < HSE_SQNREF_TO_ORDNL(ref)) {
            diff = seqnoref_ext_diff(ord, ref);
            ASSERT_EQ(ULONG_MAX, diff);
        } else {
            diff = seqnoref_ext_diff(ord, ref);
            ASSERT_EQ(ord - 50, diff);
        }
    }

    ref = HSE_SQNREF_UNDEFINED;

    for (ord = 0; ord < 100; ++ord) {
        diff = seqnoref_ext_diff(ord, ref);
        ASSERT_EQ(ULONG_MAX, diff);
    }
}

MTF_DEFINE_UTEST(seqno_test, seqno_test_seqnoref_diff)
{
    uintptr_t ref0, ref1;
    u64       ord;
    u64       diff;

    ref0 = HSE_ORDNL_TO_SQNREF(50);

    for (ord = 0; ord < 100; ++ord) {
        ref1 = HSE_ORDNL_TO_SQNREF(ord);

        if (ord > HSE_SQNREF_TO_ORDNL(ref0)) {
            diff = seqnoref_diff(ref0, ref1);
            ASSERT_EQ(ULONG_MAX, diff);
        } else {
            diff = seqnoref_diff(ref0, ref1);
            ASSERT_EQ(50 - ord, diff);
        }
    }

    ref0 = HSE_SQNREF_UNDEFINED;
    ref1 = HSE_ORDNL_TO_SQNREF(3);

    diff = seqnoref_diff(ref0, ref1);
    ASSERT_EQ(ULONG_MAX, diff);

    ref0 = HSE_ORDNL_TO_SQNREF(3);
    ref1 = HSE_SQNREF_UNDEFINED;

    diff = seqnoref_diff(ref0, ref1);
    ASSERT_EQ(ULONG_MAX, diff);
}

#include <signal.h>
#include <setjmp.h>

static sig_atomic_t sigabrt_cnt;
sigjmp_buf          env;

void
sigabrt_isr(int sig)
{
    ++sigabrt_cnt;
    siglongjmp(env, 1);
}

int
signal_reliable(int signo, __sighandler_t func)
{
    struct sigaction nact;

    memset(&nact, 0, sizeof(nact));
    nact.sa_handler = func;
    sigemptyset(&nact.sa_mask);

    if (SIGALRM == signo || SIGINT == signo)
        nact.sa_flags |= SA_INTERRUPT;
    else
        nact.sa_flags |= SA_RESTART;

    return sigaction(signo, &nact, (struct sigaction *)0);
}

MTF_DEFINE_UTEST(seqno_test, seqno_test_assert)
{
    enum hse_seqno_state state;
    uintptr_t            seqno, ref, chk;

    /* seqnoref_to_state() calls abort() if the seqno is garbage.
     * So we catch the call to abort.
     */
    signal_reliable(SIGABRT, sigabrt_isr);

    state = HSE_SQNREF_STATE_ABORTED;
    ref = 0;
    seqno = HSE_REF_TO_SQNREF(&ref);

    if (0 == sigsetjmp(env, 1))
        state = seqnoref_to_seqno(seqno, &chk);

    /* If assert() is enabled then seqnoref_to_seqno() will quietly
     * succeed and return HSE_SQNREF_STATE_INVALID.  Otherwise, the
     * assert will fire and the we'll jump back to a context in
     * which state contains its initial value.
     */
#ifdef NDEBUG
    ASSERT_EQ(state, HSE_SQNREF_STATE_INVALID);
    ASSERT_EQ(0, sigabrt_cnt);
#else
    ASSERT_EQ(state, HSE_SQNREF_STATE_ABORTED);
    ASSERT_EQ(1, sigabrt_cnt);
#endif
}

MTF_END_UTEST_COLLECTION(seqno_test);
