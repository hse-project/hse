/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVS_CN_CN_NODE_LOC_H
#define HSE_KVS_CN_CN_NODE_LOC_H

#include <hse_util/platform.h>
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

/**
 * cn_tree_max_depth() - get max supported cn tree depth for a given fanout
 * @fbits: fanout, in bits (e.g.: fbits = 3 --> fanout of 8)
 *
 * The max number of levels a cn tree is determined by:
 *   - H : width of spill hash in bits
 *   - F : number of hash bits used for fanout
 *   - N : with of variable used to track node offset
 *
 * Each spill consumes F bits, thus there can be at most H/F spills, which
 * limits depth to at most H/F:
 *
 *    limit_1 = H / F
 *
 * In addition, there cannot be more than (2^N)-1 nodes in any level.  This
 * limits depth to at most:
 *
 *    limit_2 = int(log( (2^N)-1, base=2^F ))
 *
 * For example: F = 3; fanout=8;  N=32;  int(log(U32_MAX, 8)) == 10.
 * Thus, with fanout of 8, a 32-bit var cannot track node offsets
 * beyond depth 10:
 *
 *    nodes at depth 10 == 8^10 == 1073741824 < U32_MAX
 *    nodes at depth 11 == 8^11 == 8589934592 > U32_MAX
 *
 * The max tree depth is the minimum of limit_1 and limit_2.  For a 64-bit
 * hash (H=64), and 32-bit node offsets (N=32), the limits are:
 *
 * fbits  fanout   H   N  limit_1  limit_2  max_depth         leaves  leaves/M
 *     1       2  64  32       64       31         31  2,147,483,648      2048
 *     2       4  64  32       32       15         15  1,073,741,824      1024
 *     3       8  64  32       21       10         10  1,073,741,824      1024
 *     4      16  64  32       16        7          7    268,435,456       256
 *     5      32  64  32       12        6          6  1,073,741,824      1024
 *     6      64  64  32       10        5          5  1,073,741,824      1024
 *     7     128  64  32        9        4          4    268,435,456       256
 *     8     256  64  32        8        3          3     16,777,216        16
 *     9     512  64  32        7        3          3    134,217,728       128
 *    10    1024  64  32        6        3          3  1,073,741,824      1024
 *    11    2048  64  32        5        2          2      4,194,304         4
 *    12    4096  64  32        5        2          2     16,777,216        16
 */
static inline uint
cn_tree_max_depth(uint fbits)
{
    uint depth[] = { 0, 31, 15, 10, 7, 6, 5, 4, 3, 3, 3, 2, 2 };

    assert(CN_FANOUT_BITS_MAX + 1 == NELEM(depth));
    assert(CN_FANOUT_BITS_MAX >= fbits);
    assert(CN_FANOUT_BITS_MIN <= fbits);

    return depth[fbits];
}

/**
 * nodes_in_level() - returns the maximun number of nodes in given level
 * @fanout_bits: bits used for fanout (e.g.: fanout_bits = 3 --> fanout of 8)
 * @level: tree level (root node at level 0)
 *
 * Number of nodes in level L of tree with fanout F == 2^B is given by:
 *
 *    F^L == (2^B)^L == 2^(B*L) == 1<<(B*L)
 *
 */
static inline u32
nodes_in_level(u32 fanout_bits, u32 level)
{
    assert(fanout_bits * level < 32);
    return (u32)1 << (fanout_bits * level);
}

/**
 * node_parent_offset() - returns the offset of a given node's parent
 *
 * Examples (reference ascii art at top of file):
 *
 *  Fanout=4, Bits=2
 *  ----------------
 *    parent of (2,6) is (1,1):
 *      parent_offset == 6>>BITS == 1
 *      parent_node   == (1,1)
 *
 *    parent of (2,12) is (1,3):
 *      parent_offset == 12>>BITS == 12>>2 == 3
 *      parent_node   == (1,3)
 *
 *  Fanout=2, Bits=1
 *  ----------------
 *    parent of (3,7) is (2,3):
 *      parent_offset == 7>>BITS == 7>>1 == 3
 *      parent_node   == (2,3)
 */
static inline u32
node_parent_offset(u32 fanout_bits, struct cn_node_loc *loc)
{
    return loc->node_offset >> fanout_bits;
}

/**
 * node_nth_child_offset() - returns the offset of a given node's n-th child
 *
 * Examples (reference ascii art at top of file):
 *
 *  Fanout=4, Bits=2
 *  ----------------
 *    node(1,1).child[2] is (2,6):
 *      child[2].offset == (1<<2) + 2 == 6
 *      child[2].node   == (2,6)
 *
 *    node(1,3).child[0] is (2,12):
 *      child[0].offset == (3<<2) + 0 == 12
 *      child[0].node   == (2,12)
 *
 *  Fanout=2, Bits=1
 *  ----------------
 *    node(2,3).child[1] is (3,7):
 *      child[1].offset == (3<<1) + 1 == 7
 *      child[2].node   == (3,7)
 */
static inline u32
node_nth_child_offset(u32 fanout_bits, struct cn_node_loc *loc, u32 nth)
{
    return (loc->node_offset << fanout_bits) + nth;
}

static inline u32
node_first_child_offset(u32 fanout_bits, struct cn_node_loc *loc)
{
    return node_nth_child_offset(fanout_bits, loc, 0);
}

#endif
