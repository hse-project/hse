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
        kvs_ctx = lifecycle.KvsContext(kvdb, "cache_delay")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")
        kvs.put(b"c", b"3")

        cursor = kvs.cursor()

        kv = cursor.read()
        assert kv == (b"a", b"1")

        kvs.put(b"d", b"4")

        kv = cursor.read()
        assert kv == (b"b", b"2")
        kv = cursor.read()
        assert kv == (b"c", b"3")
        cursor.read()
        assert cursor.eof

        cursor.destroy()

        cursor = kvs.cursor()

        kv = cursor.read()
        assert kv == (b"a", b"1")
        kv = cursor.read()
        assert kv == (b"b", b"2")
        kv = cursor.read()
        assert kv == (b"c", b"3")
        kv = cursor.read()
        assert kv == (b"d", b"4")
        cursor.read()
        assert cursor.eof

        cursor.destroy()

        kvs.put(b"e", b"5")

        cursor = kvs.cursor()

        assert sum(1 for _ in cursor.items()) == 5

        cursor.destroy()
finally:
    hse.fini()
