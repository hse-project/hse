/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_KVDB_DIAG_H
#define HSE_KVDB_DIAG_H

#include <hse/limits.h>
#include <hse/types.h>

/* Opaque handles */
struct kvdb;
struct cndb;

struct diag_kvdb_kvs_list {
    unsigned long kdl_cnid;
    char          kdl_name[HSE_KVS_NAME_LEN_MAX];
};

/**
 * diag_kvdb_kvslist() - obtain a list of kvses known to kvdb
 * @kvdb:         handle obtained from diag_kvdb_open()
 * @list:         pointer to an arrar of descriptors
 * @len:          the number of descriptors allocated for the array
 * @kvscnt:       (output) the number of kvses known to kvdb
 *
 * If kvscnt > len, the array contains the first len kvses.
 */
merr_t
diag_kvdb_kvslist(struct hse_kvdb *kvdb, struct diag_kvdb_kvs_list *list, int len, int *kvscnt);

/**
 * diag_kvdb_open() - open a kvdb for diagnostic purposes.
 * @kvdb_home:      kvdb home
 * @kvdb:           (output) handle to access the opened KVDB
 *
 * kvdb is opened with minimal processing. The kvdb root metadata is recovered.
 * Other media resources are left opened but un-read, and corresponding
 * memory structures are minimally instantiated.  Background maintenance is
 * not started.
 */
merr_t
diag_kvdb_open(
    const char *       kvdb_home,
    size_t             paramc,
    const char *const *paramv,
    struct hse_kvdb ** kvdb);

/**
 * diag_kvdb_close() - close a kvdb opened for diagnostic purposes
 * @kvdb:         handle obtained from diag_kvdb_open()
 *
 * Behavior is undefined if the handle was opened with kvdb_open();
 */
merr_t
diag_kvdb_close(struct hse_kvdb *handle);

/**
 * diag_kvdb_get_cndb() - obtain a pointer to cndb
 * @kvdb:         handle obtained from diag_kvdb_open()
 * @cndb:         (output) pointer to cndb
 */
merr_t
diag_kvdb_get_cndb(struct hse_kvdb *kvdb, struct cndb **cndb);

#endif
