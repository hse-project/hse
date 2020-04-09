/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_RPARAM_DEBUG_FLAGS_H
#define HSE_IKVDB_RPARAM_DEBUG_FLAGS_H

/* struct kvdb_rparams : c0_debug */
#define C0_DEBUG_INGENQ 0x00000001
#define C0_DEBUG_INGTUNE 0x00000002
#define C0_DEBUG_INGSPILL 0x00000004
#define C0_DEBUG_SYNC 0x00000008
#define C0_DEBUG_ACCUMULATE 0x00000010

/* struct kvdb_rparams : throttle_debug */
#define THROTTLE_DEBUG_DELAY 0x00000001
#define THROTTLE_DEBUG_DELAYV 0x00000002
#define THROTTLE_DEBUG_REDUCE 0x00000004
#define THROTTLE_DEBUG_SENSOR_C0SK 0x00000008
#define THROTTLE_DEBUG_SENSOR_C1 0x00000010
#endif
