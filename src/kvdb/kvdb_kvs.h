/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_KVS_H
#define HSE_IKVDB_KVS_H

#include <hse_util/inttypes.h>
#include <hse_util/list.h>
#include <hse_util/mutex.h>
#include <hse_util/compression.h>

struct ikvs;
struct ikvdb_impl;
struct kvdb_kvs;

struct kk_cursors_mtx {
    struct mutex mtx;
} __aligned(SMP_CACHE_BYTES * 2);

/**
 * struct kvdb_kvs - Describes a kvs in the kvdb - open or closed
 * @kk_ikvs:         kvs handle. NULL if closed.
 * @kk_seqno:        pointer to parent->ikdb_seqno
 * @kk_seqno_cur:    pointer to parent->ikdb_seqno_cur
 * @kk_parent:       pointer to parent kvdb_impl instance.
 * @kk_vcompmin:     value length above which compression is considered
 * @kk_vcompbnd:     compression output buffer size estimate for tls_vbuf[]
 * @kk_vcompress:    ptr to value compression function
 * @kk_cnid:         id of the cn associated with kvdb.
 * @kk_cparams:      cn's create-time parameters.
 * @kk_flags:        flags for cn.
 * @kk_refcnt:       count of current users of the instance. Used mainly to
 *                   synchronize with rest requests.
 * @kk_cursors_mtxv: array of mutexes to reduce contention on @kk_cursors_spin
 * @kk_cursors_spin: spinlock to protect @kk_cursors_list
 * @kk_cursors_list: list of cursors currently traversing the cn tree.
 * @kk_name:         kvs name.
 *
 * To access @kk_cursor_list one must acquire @kk_cursors_spin.  To reduce
 * contention on @kk_cursors_spin, first acquire one of the mutexes in the
 * @kk_cursors_mtxv array.
 */
struct kvdb_kvs {
    struct ikvs            *kk_ikvs;
    atomic64_t             *kk_seqno;
    atomic64_t             *kk_seqno_cur;
    struct ikvdb_impl      *kk_parent;
    u32                     kk_vcompmin;
    u32                     kk_vcompbnd;
    compress_op_compress_t *kk_vcompress;
    u64                     kk_cnid;
    struct kvs_cparams     *kk_cparams;
    u32                     kk_flags;
    atomic_t                kk_refcnt;

    struct kk_cursors_mtx kk_cursors_mtxv[3];
    spinlock_t            kk_cursors_spin;
    struct list_head      kk_cursors_list;

    char kk_name[HSE_KVS_NAME_LEN_MAX];
};

#endif
