#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

# creates 1million + prefixes, adds data to each prefix and validates.

# Test params
# total number of prefixes
NUM_PFXS = 1024 * 1024 + 1024
# number of keys per prefix
NUM_KEYS = 10

hse.init(cli.CONFIG)


def create_pfx_data(kvdb: hse.Kvdb, kvs: hse.Kvs, pfx: int):
    pfx_bytes = pfx.to_bytes(4, byteorder="big")

    with kvdb.transaction() as txn:
        for sfx in range(NUM_KEYS):
            key = pfx_bytes + sfx.to_bytes(1, byteorder="big")
            kvs.put(key, key, txn=txn)


def verify_pfx_data(kvdb: hse.Kvdb, kvs: hse.Kvs, pfx: int):
    pfx_bytes = pfx.to_bytes(4, byteorder="big")

    with kvdb.transaction() as txn, kvs.cursor(filt=pfx_bytes,
                                               txn=txn) as cursor:
        for sfx in range(NUM_KEYS):
            key_exp = pfx_bytes + sfx.to_bytes(1, byteorder="big")
            key, val = cursor.read()
            assert key == key_exp
            assert val == key_exp
        cursor.read()
        assert cursor.eof


try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "kvs_many_pfx").rparams(
            "transactions.enabled=true"
        )
        kvs = stack.enter_context(kvs_ctx)

        for pfx in range(NUM_PFXS):
            create_pfx_data(kvdb, kvs, pfx)

        for pfx in range(NUM_PFXS):
            verify_pfx_data(kvdb, kvs, pfx)
finally:
    hse.fini()
