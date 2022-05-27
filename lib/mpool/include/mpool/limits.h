/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef MPOOL_LIMITS_H
#define MPOOL_LIMITS_H

#define MPOOL_MBLOCK_SIZE_MIN          (2ul << MB_SHIFT)
#define MPOOL_MBLOCK_SIZE_MAX          (1024ul << MB_SHIFT)
#define MPOOL_MBLOCK_SIZE_DEFAULT      (32ul << MB_SHIFT)

#define MPOOL_MCLASS_FILECNT_MIN       (1)
#define MPOOL_MCLASS_FILECNT_MAX       (UINT8_MAX)
#define MPOOL_MCLASS_FILECNT_DEFAULT   (32)

#define MPOOL_MCLASS_FILESZ_MIN        (64ull << GB_SHIFT)
#define MPOOL_MCLASS_FILESZ_MAX        (65536ull << GB_SHIFT)
#define MPOOL_MCLASS_FILESZ_DEFAULT    (2048ull << GB_SHIFT)

#endif /* MPOOL_LIMITS_H */
