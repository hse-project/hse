/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_RPARAM_DEBUG_FLAGS_H
#define HSE_IKVDB_RPARAM_DEBUG_FLAGS_H

/* struct kvdb_rparams : c0_debug */
#define C0_DEBUG_INGTUNE    0x02
#define C0_DEBUG_INGSPILL   0x04
#define C0_DEBUG_SYNC       0x08
#define C0_DEBUG_ACCUMULATE 0x10

/* struct kvdb_rparams : throttle_debug */
#define THROTTLE_DEBUG_DELAY       0x00000001
#define THROTTLE_DEBUG_DELAYV      0x00000002
#define THROTTLE_DEBUG_REDUCE      0x00000004
#define THROTTLE_DEBUG_SENSOR_C0SK 0x00000008
#define THROTTLE_DEBUG_SENSOR_C1   0x00000010
#define THROTTLE_DEBUG_TB_MASK     0xffff0000 /* token bucket debug flags */
#define THROTTLE_DEBUG_TB_DEBUG    0x00010000
#define THROTTLE_DEBUG_TB_MANUAL   0x00100000
#define THROTTLE_DEBUG_TB_SHUNT    0x01000000

#endif
