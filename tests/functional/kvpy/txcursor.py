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
        kvs_ctx = lifecycle.KvsContext(kvdb, "txcursor").rparams("transactions.enabled=true")
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"a", b"1", txn=txn)
            kvs.put(b"b", b"2", txn=txn)
            kvs.put(b"c", b"3", txn=txn)

        txn1 = kvdb.transaction()
        txn1.begin()

        with kvdb.transaction() as t:
            kvs.put(b"d", b"4", txn=t)

        cursor = kvs.cursor(txn=txn1)

        kvs.put(b"a", b"5", txn=txn1)

        kv = cursor.read()
        assert kv == (b"a", b"5")
        kv = cursor.read()
        assert kv == (b"b", b"2")
        kv = cursor.read()
        assert kv == (b"c", b"3")
        cursor.read()
        assert cursor.eof

        cursor.destroy()

        # Exit without committing/aborting txn1

finally:
    hse.fini()
