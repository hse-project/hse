/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc. All rights reserved.
 */
#ifndef KVS_HELPER_H
#define KVS_HELPER_H

#include <stdint.h>
#include <stdlib.h>

#include <hse/hse.h>

#include "tools/common.h"
#include "tools/parm_groups.h"

typedef void
kh_func(void *);

struct kh_thread_arg {
    void *arg;
    struct hse_kvdb *kvdb;
    struct hse_kvs *kvs;
    uint64_t seed;
};

struct hse_kvdb *
kh_init(
    const char *config,
    const char *kvdb_home,
    struct svec *hse_gparms,
    struct svec *kvdb_oparms);

void
kh_fini(void);

enum kh_flags {
    KH_FLAG_DETACH = 0x01,
};

void
kh_wait(void);

void
kh_wait_all(void);

int
kh_register_kvs(
    const char *kvs,
    enum kh_flags flags,
    struct svec *kvs_cparms,
    struct svec *kvs_oparms,
    kh_func *func,
    void *arg);

int
kh_register(enum kh_flags flags, kh_func *func, void *arg);

/* cursor helper functions */
struct hse_kvs_cursor *
kh_cursor_create(
    struct hse_kvs *kvs,
    unsigned int flags,
    struct hse_kvdb_txn *txn,
    void *pfx,
    size_t pfxlen);

void
kh_cursor_update_view(struct hse_kvs_cursor *cur, unsigned int flags);

void
kh_cursor_seek(struct hse_kvs_cursor *cur, void *key, size_t klen);

void
kh_cursor_seek_limited(
    struct hse_kvs_cursor *cur,
    void *from,
    size_t from_len,
    void *to,
    size_t to_len);

bool
kh_cursor_read(
    struct hse_kvs_cursor *cur,
    const void **key,
    size_t *klen,
    const void **val,
    size_t *vlen);

void
kh_cursor_destroy(struct hse_kvs_cursor *cur);

#endif /* KVS_HELPER_H */
