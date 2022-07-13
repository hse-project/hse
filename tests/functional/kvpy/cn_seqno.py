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
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "cn_seqno").rparams(
            "transactions.enabled=true"
        )
        kvs = stack.enter_context(kvs_ctx)

        txn = kvdb.transaction()
        txn.begin()

        with kvdb.transaction() as t:
            kvs.put(b"a", b"1", txn=t)

        kvdb.sync()

        txcursor = kvs.cursor(txn=txn)
        txcursor.read()
        assert txcursor.eof

        txn.abort()
        txcursor.seek(b"0")
        kv = txcursor.read()
        assert txcursor.eof

        txcursor.destroy()
finally:
    hse.fini()
