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
        kvs_ctx = lifecycle.KvsContext(kvdb, "bug_update_new_kvms")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")

        cursor = kvs.cursor()
        kv = cursor.read()
        assert kv == (b"a", b"1")
        kv = cursor.read()
        assert kv == (b"b", b"2")
        cursor.read()
        assert cursor.eof

        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        kvs.put(b"c", b"3")
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        kvs.put(b"d", b"4")
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        kvs.put(b"e", b"5")
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        kvs.put(b"f", b"6")

        with kvdb.transaction() as txn:
            kvs.put(b"c", b"3")

        cursor.update_view()
        cursor.seek(b"0x00")

        assert sum(1 for _ in cursor.items()) == 6

        cursor.destroy()
finally:
    hse.fini()
