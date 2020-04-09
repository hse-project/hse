/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_PERFC_H
#define HSE_C1_PERFC_H

void
c1_perfc_alloc(struct c1 *c1, const char *mpname);

void
c1_perfc_journal_alloc(struct perfc_set *cset, const char *mpname);

/**
 * c1_perfc_journal_free()
 * @pcset:
 *
 * Free the perf counter set for this journal instance.
 */
void
c1_perfc_journal_free(struct perfc_set *pcset);

/**
 * c1_perfc_io_free()
 * @pcset:
 *
 * Free the perf counter set for this io instance.
 */
void
c1_perfc_io_free(struct perfc_set *pcset);

/**
 * c1_perfc_free()
 * @c1:
 *
 * Free the perf counter sets for this c1 instance.
 */
void
c1_perfc_free(struct c1 *c1);

void
c1_perfc_io_alloc(struct perfc_set *cset, const char *mpname);

#endif /* HSE_C1_PERFC_H */
