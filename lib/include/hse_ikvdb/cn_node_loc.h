/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020,2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_CN_NODE_LOC_H
#define HSE_KVS_CN_CN_NODE_LOC_H

#include <hse_util/platform.h>
#include <hse_util/log2.h>

#include <hse_ikvdb/limits.h>

/**
 * struct cn_node_loc -- describes a node's location in a tree
 *
 * The position, or location, of a node in a tree can be described by a
 * tuple '(@level,@offset)', where @level is the tree level in which the
 * node resides and @offset is the offset of the node within that level.
 *
 * Example trees are shown below.  Note that the @offset increment
 * across all nodes in a level, and the root node's position is always
 * '(0,0)'.
 *
 *
 *        Fanout=4 (bits=2)             Fanout=2 (bits=1)
 *        -------------------           -------------------------
 *        (0,0)                         (0,0)
 *            |--(1,0)                      |--(1,0)
 *            |      |--(2,0)               |      |--(2,0)
 *            |      |--(2,1)               |      |      |--(3,0)
 *            |      |--(2,2)               |      |      `--(3,1)
 *            |      `--(2,3)               |      `--(2,1)
 *            |--(1,1)                      |             |--(3,2)
 *            |      |--(2,4)               |             `--(3,3)
 *            |      |--(2,5)               `--(1,1)
 *            |      |--(2,6)                      |--(2,2)
 *            |      `--(2,7)                      |      |--(3,4)
 *            |--(1,2)                             |      `--(3,5)
 *            |      |--(2,8)                      `--(2,3)
 *            |      |--(2,9)                             |--(3,6)
 *            |      |--(2,10)                            `--(3,7)
 *            |      `--(2,11)
 *            `--(1,3)
 *                  |--(2,12)
 *                  |--(2,13)
 *                  |--(2,14)
 *                  `--(2,15)
 *
 * This file contains functions to facilitate navigating trees using
 * this naming convention.
 */

/* Location of a node in the tree */
struct cn_node_loc {
    u32 node_level;
    u32 node_offset;
};

#endif
