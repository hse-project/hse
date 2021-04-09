/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_PLATFORM_PLATFORM_H
#define HSE_PLATFORM_PLATFORM_H

/* include this first */
#include <hse_util/base.h>

/* the rest in alphabetic order */
#include <hse_util/alloc.h>
#include <hse_util/arch.h>
#include <hse_util/assert.h>
#include <hse_util/atomic.h>
#include <hse_util/barrier.h>
#include <hse_util/bin_heap.h>
#include <hse_util/byteorder.h>
#include <hse_util/byteorder.h>
#include <hse_util/compiler.h>
#include <hse_util/condvar.h>
#include <hse_util/cursor_heap.h>
#include <hse_util/delay.h>
#include <hse_util/delay.h>
#include <hse_util/hse_err.h>
#include <hse_util/inttypes.h>
#include <hse_util/inttypes.h>
#include <hse_util/keycmp.h>
#include <hse_util/list.h>
#include <hse_util/logging.h>
#include <hse_util/minmax.h>
#include <hse_util/mutex.h>
#include <hse_util/page.h>
#include <hse_util/parse_num.h>
#include <hse_util/printbuf.h>
#include <hse_util/rwsem.h>
#include <hse_util/spinlock.h>
#include <hse_util/time.h>
#include <hse_util/timing.h>
#include <hse_util/uuid.h>
#include <hse_util/workqueue.h>

/* For open/close/read/write */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

extern merr_t hse_platform_init(void);
extern void hse_platform_fini(void);

#endif /* HSE_PLATFORM_PLATFORM_H */
