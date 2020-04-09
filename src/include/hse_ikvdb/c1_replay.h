/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_C1_REPLAY_H
#define HSE_C1_REPLAY_H

struct ikvdb;
struct kvdb_rparams;
struct ikvdb_c1_replay;

/**
 * ikvdb_c1_replay_open() - Open kvses inside a kvdb for replay by c1
 * @ikdb:   kvdb handle
 * @replay (output): Opaque structure represeting all opened kvses inside kvdb.
 */
merr_t
ikvdb_c1_replay_open(struct ikvdb *ikdb, struct ikvdb_c1_replay **replay);

/**
 * ikvdb_c1_replay_close() - Close kvses inside a kvdb after replay by c1
 * @ikdb:   kvdb handle
 * @replay: Opaque structure represeting all kvses which need to be closed
 */
merr_t
ikvdb_c1_replay_close(struct ikvdb *ikdb, struct ikvdb_c1_replay *replay);

/**
 * ikvdb_c1_replay_put() - Replay handler for kvdb put operations
 * @ikdb:   kvdb handle
 * @replay: Opaque structure represeting all kvses inside kvdb
 * @seqno:  Sequence number saved in c1
 * @cnid:   Unique CNID representing a kvs in kvdb
 * @os:     kvdb_opspec structure
 * @kt:     key tuple
 * @vt:     value tuple
 */
merr_t
ikvdb_c1_replay_put(
    struct ikvdb *           ikdb,
    struct ikvdb_c1_replay * replay,
    u64                      seqno,
    u64                      cnid,
    struct hse_kvdb_opspec * os,
    struct kvs_ktuple *      kt,
    const struct kvs_vtuple *vt);

/**
 * ikvdb_c1_replay_del() - Replay handler for kvdb delete operations
 * @ikdb:   kvdb handle
 * @replay: Opaque structure represeting all kvses inside kvdb
 * @seqno:  Sequence number saved in c1
 * @cnid:   Unique CNID representing a kvs in kvdb
 * @os:     kvdb_opspec structure
 * @kt:     key tuple
 * @vt:     value tuple
 */
merr_t
ikvdb_c1_replay_del(
    struct ikvdb *          ikdb,
    struct ikvdb_c1_replay *replay,
    u64                     seqno,
    u64                     cnid,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *     kt,
    struct kvs_vtuple *     vt);

/**
 * ikvdb_c1_set_seqno() - Set kvdb seqno post reply
 * @replay: Opaque structure represeting all kvses inside kvdb
 * @seqno:  new kvdb sequence number
 */
void
ikvdb_c1_set_seqno(struct ikvdb *ikdb, u64 seqno);

#endif /* HSE_C1_REPLAY_H */
