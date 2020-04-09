/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_KVS_H
#define HSE_IKVDB_KVS_H

#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/mutex.h>

struct ikvs;
struct ikvdb_impl;
struct kvdb_kvs;

/**
 * struct kvdb_kvs - Describes a kvs in the kvdb - open or closed
 *
 * @kk_ikvs:         kvs handle. NULL if closed.
 * @kk_parent:       pointer to parent kvdb_impl instance.
 * @kk_cnid:         id of the cn associated with kvdb.
 * @kk_cparams:      cn's create-time parameters.
 * @kk_flags:        flags for cn.
 * @kk_cursors_lock: lock to access the list.
 * @kk_cursors:      list of cursors currently traversing the cn tree.
 * @kk_refcnt:       count of current users of the instance. Used mainly to
 *                   synchronize with rest requests.
 * @kk_name:         kvs name.
 */
struct kvdb_kvs {
    struct ikvs *       kk_ikvs;
    struct ikvdb_impl * kk_parent;
    u64                 kk_cnid;
    struct kvs_cparams *kk_cparams;
    u32                 kk_flags;

    __aligned(SMP_CACHE_BYTES) struct mutex kk_cursors_lock;
    struct list_head kk_cursors;

    __aligned(SMP_CACHE_BYTES) atomic_t kk_refcnt;

    char kk_name[HSE_KVS_NAME_LEN_MAX];
};

#endif
