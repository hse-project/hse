/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
 */

#ifndef HSE_UTIL_STORAGE_H
#define HSE_UTIL_STORAGE_H

#define KB_SHIFT (10)
#define MB_SHIFT (20)
#define GB_SHIFT (30)
#define TB_SHIFT (40)

#define KB (1ul << KB_SHIFT)
#define MB (1ul << MB_SHIFT)
#define GB (1ul << GB_SHIFT)
#define TB (1ull << TB_SHIFT)

#endif
