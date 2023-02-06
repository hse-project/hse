/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

/*
 * CN performance counter family.
 *
 * There is one counter set per logical operation of CN.
 */

#ifndef HSE_IKVDB_CN_PERFC_H
#define HSE_IKVDB_CN_PERFC_H

void
cn_perfc_init(void);

void
cn_perfc_fini(void);

#endif
