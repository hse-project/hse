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
        kvs_ctx = lifecycle.KvsContext(kvdb, "bind_committed").rparams("transactions.enabled=true")
        kvs = stack.enter_context(kvs_ctx)

        txn = kvdb.transaction()
        txn.begin()

        txcursor = kvs.cursor(txn=txn)
        kvs.put(b"a", b"1", txn=txn)
        kvs.put(b"b", b"2", txn=txn)
        kvs.put(b"c", b"3", txn=txn)
        kv = txcursor.read()
        assert kv == (b"a", b"1")

        txn.commit()
        txn.begin()
        kvs.put(b"a", b"12", txn=txn)
        kvs.put(b"b", b"22", txn=txn)
        kvs.put(b"c", b"32", txn=txn)

        kv = txcursor.read()
        assert kv == (b"b", b"22")
        kv = txcursor.read()
        assert kv == (b"c", b"32")

        with kvdb.transaction() as t:
            cursor = kvs.cursor(txn=t)
            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"2")
            kv = cursor.read()
            assert kv == (b"c", b"3")
            cursor.read()
            assert cursor.eof
            cursor.destroy()

        txcursor.seek(b"0")
        kv = txcursor.read()
        assert kv == (b"a", b"12")
        kv = txcursor.read()
        assert kv == (b"b", b"22")
        kv = txcursor.read()
        assert kv == (b"c", b"32")
        txcursor.read()
        assert txcursor.eof

        txcursor.destroy()
finally:
    hse.fini()
