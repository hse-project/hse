#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "bug_skidx_not_in_c0_kvset").rparams(
            "transactions.enabled=true"
        )
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"0x000000012b0204", b"key1", txn=txn)

        with kvdb.transaction() as txn:
            kvs.put(b"0x000000012b0404", b"key2", txn=txn)

        with kvdb.transaction() as txn:
            kvs.put(b"0x000000012b0604", b"key3", txn=txn)

        with kvdb.transaction() as txn:
            with kvs.cursor(txn=txn) as cur:
                cur.seek(b"0x000000012b0404")
                _, value = cur.read()

            assert value == b"key2"
finally:
    hse.fini()
