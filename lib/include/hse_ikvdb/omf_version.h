/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_OMF_VERSION_H
#define HSE_KVDB_OMF_VERSION_H

#include <inttypes.h>

enum {
    GLOBAL_OMF_VERSION1 = 1,
    GLOBAL_OMF_VERSION2 = 2,
};

enum {
    CNDB_VERSION4 = 4,
    CNDB_VERSION5 = 5,
    CNDB_VERSION6 = 6,
    CNDB_VERSION7 = 7,
    CNDB_VERSION8 = 8,
    CNDB_VERSION9 = 9,
    CNDB_VERSION10 = 10,
    CNDB_VERSION11 = 11,
    CNDB_VERSION12 = 12,
};

enum {
    KBLOCK_HDR_VERSION2 = 2,
    KBLOCK_HDR_VERSION3 = 3,
    KBLOCK_HDR_VERSION4 = 4,
    KBLOCK_HDR_VERSION5 = 5,
};

enum {
    VBLOCK_HDR_VERSION1 = 1,
    VBLOCK_HDR_VERSION2 = 2,
};

enum {
    BLOOM_OMF_VERSION5 = 5,
};

enum {
    WBT_TREE_VERSION2 = 2,
    WBT_TREE_VERSION3 = 3,
    WBT_TREE_VERSION4 = 4,
    WBT_TREE_VERSION5 = 5,
    WBT_TREE_VERSION6 = 6,
};

enum {
    CN_TSTATE_VERSION1 = 1,
};

enum {
    MBLOCK_METAHDR_VERSION1 = 1,
    MBLOCK_METAHDR_VERSION2 = 2,
};

enum {
    MDC_LOGHDR_VERSION1 = 1,
    MDC_LOGHDR_VERSION2 = 2,
};

enum {
    WAL_VERSION1 = 1,
};

enum {
    KVDB_META_VERSION1 = 1,
};

#define GLOBAL_OMF_VERSION GLOBAL_OMF_VERSION2

/* In the event one of the following versions in incremented, increment the
 * global OMF version.
 */

#define CNDB_VERSION           CNDB_VERSION12
#define KBLOCK_HDR_VERSION     KBLOCK_HDR_VERSION5
#define VBLOCK_HDR_VERSION     VBLOCK_HDR_VERSION2
#define BLOOM_OMF_VERSION      BLOOM_OMF_VERSION5
#define WBT_TREE_VERSION       WBT_TREE_VERSION6
#define CN_TSTATE_VERSION      CN_TSTATE_VERSION1
#define MBLOCK_METAHDR_VERSION MBLOCK_METAHDR_VERSION2
#define MDC_LOGHDR_VERSION     MDC_LOGHDR_VERSION2
#define WAL_VERSION            WAL_VERSION1
#define KVDB_META_VERSION      KVDB_META_VERSION1

#endif
