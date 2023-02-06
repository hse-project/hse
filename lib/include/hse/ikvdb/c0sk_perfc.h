/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

/*
 * C0SK performance counter family.
 *
 * There is one counter set per logical instance of c0sk
 */

#ifndef C0SK_PERFC_H
#define C0SK_PERFC_H

struct c0sk_impl;

void
c0sk_perfc_init(void);

void
c0sk_perfc_fini(void);

void
c0sk_perfc_alloc(struct c0sk_impl *self);

void
c0sk_perfc_free(struct c0sk_impl *self);

#endif
