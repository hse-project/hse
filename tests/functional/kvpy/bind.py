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
        kvs1_ctx = lifecycle.KvsContext(kvdb, "bind-1").rparams("transactions.enabled=true")
        kvs2_ctx = lifecycle.KvsContext(kvdb, "bind-2").rparams("transactions.enabled=true")
        kvs1 = stack.enter_context(kvs1_ctx)
        kvs2 = stack.enter_context(kvs2_ctx)

        with kvdb.transaction() as txn:
            kvs1.put(b"a", b"1", txn=txn)
            kvs1.put(b"b", b"1", txn=txn)
            kvs1.put(b"c", b"1", txn=txn)

        with kvdb.transaction() as txn:
            kvs2.put(b"a", b"2", txn=txn)
            kvs2.put(b"b", b"2", txn=txn)
            kvs2.put(b"c", b"2", txn=txn)

        with kvdb.transaction() as txn:
            cursor = kvs1.cursor(txn=txn)

            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"1")
            kv = cursor.read()
            assert kv == (b"c", b"1")
            cursor.read()
            assert cursor.eof

            kvs1.put(b"d", b"1", txn=txn)
            cursor.seek(b"d")

            kv = cursor.read()
            assert kv == (b"d", b"1")

            txn.abort()
            cursor.seek(b"a")
            try:
                cursor.read()
                assert False
            except:
                pass

            cursor.destroy()

        txn = kvdb.transaction()
        txn.begin()
        kvs2.put(b"d", b"2", txn=txn)

        cursor1 = kvs2.cursor(txn=txn)
        cursor1.seek(b"d")
        kv = cursor1.read()
        assert kv == (b"d", b"2")
        cursor1.read()
        assert cursor1.eof
        txn.commit()

        with kvdb.transaction() as t:
            cursor2 = kvs2.cursor(txn=t)
            for k, v in cursor2.items():
                assert v == b"2"
            try:
                cursor1.read()
                assert False
            except:
                pass
            cursor2.destroy()

        cursor1.destroy()

finally:
    hse.fini()
