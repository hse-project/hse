#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "bug_skidx_not_init").rparams(
            "transactions.enabled=true"
        )
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"0x000000012b0204", b"key1", txn=txn)
            kvs.put(b"0x000000012b0404", b"key2", txn=txn)
            kvs.put(b"0x000000012b0604", b"key3", txn=txn)

            with kvs.cursor(b"0x00000001", txn=txn) as cur:
                cur.read()
                cur.read()
                cur.read()

                cur.read()
                assert cur.eof
finally:
    hse.fini()
