/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */
#ifndef HSE_WAL_H
#define HSE_WAL_H

merr_t
wal_put(
    struct ikvs *kvs,
    struct hse_kvdb_opspec *os,
    struct kvs_ktuple *kt,
    struct kvs_vtuple *vt,
    u64 seqno);

merr_t wal_init(void) HSE_COLD;
void wal_fini(void) HSE_COLD;

#endif
