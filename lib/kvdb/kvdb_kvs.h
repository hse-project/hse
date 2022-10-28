/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_IKVDB_KVS_H
#define HSE_IKVDB_KVS_H

#include <hse/limits.h>

#include <hse/ikvdb/vcomp_params.h>
#include <hse/util/atomic.h>
#include <hse/util/inttypes.h>
#include <hse/util/list.h>
#include <hse/util/mutex.h>
#include <hse/util/compression.h>

struct ikvs;
struct ikvdb_impl;
struct kvdb_kvs;

/**
 * struct kvdb_kvs - Describes a kvs in the kvdb - open or closed
 * @kk_ikvs:         kvs handle. NULL if closed.
 * @kk_parent:       pointer to parent kvdb_impl instance.
 * @kk_vcompbnd:     compression output buffer size estimate for tls_vbuf[]
 * @kk_vcompress:    ptr to value compression function
 * @kk_cnid:         id of the cn associated with kvdb.
 * @kk_cparams:      cn's create-time parameters.
 * @kk_flags:        flags for cn.
 * @kk_refcnt:       count of current users of the instance. Used mainly to
 *                   synchronize with rest requests.
 * @kk_name:         kvs name.
 */
struct kvdb_kvs {
    struct ikvs            *kk_ikvs;
    struct viewset         *kk_viewset;
    struct ikvdb_impl      *kk_parent;
    enum vcomp_default      kk_vcomp_default;
    u32                     kk_vcompbnd;
    compress_op_compress_t *kk_vcompress;
    u64                     kk_cnid;
    struct kvs_cparams     *kk_cparams;
    u32                     kk_flags;
    atomic_int              kk_refcnt;

    char kk_name[HSE_KVS_NAME_LEN_MAX];
};

#endif
