/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_THREAD_H
#define HSE_C1_THREAD_H

struct c1_thread;

merr_t
c1_thread_create(
    const char *thrname,
    void (*c1thr_fp)(void *arg),
    void *             arg,
    struct c1_thread **out);

merr_t
c1_thread_run(struct c1_thread *thr);

merr_t
c1_thread_destroy(struct c1_thread *thr);

#endif /* HSE_C1_THREAD_H */
