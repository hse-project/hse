#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack
from typing import List

from hse2 import hse

from utility import lifecycle, cli


def check_keys(cursor: hse.KvsCursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "tmobspan")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")
        kvs.put(b"c", b"3")
        kvs.put(b"d", b"4")
        kvs.put(b"e", b"5")
        kvs.put(b"f", b"6")
        kvs.put(b"g", b"7")
        kvs.put(b"h", b"8")

        cursor = kvs.cursor()
        check_keys(cursor, [b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h"])

        kvs.delete(b"a")
        kvs.delete(b"b")
        kvs.delete(b"c")
        kvs.delete(b"d")
        kvs.delete(b"e")

        cursor.update_view()
        cursor.seek(b"a")
        kv = cursor.read()
        assert kv == (b"f", b"6")
        cursor.seek(b"a")
        kv = cursor.read()
        assert kv == (b"f", b"6")

        kvs.delete(b"f")
        cursor.update_view()
        cursor.seek(b"a")
        kv = cursor.read()
        assert kv == (b"g", b"7")
        cursor.seek(b"a")
        kv = cursor.read()
        assert kv == (b"g", b"7")

        kvs.put(b"c", b"33")
        cursor.update_view()
        cursor.seek(b"a")
        kv = cursor.read()
        assert kv == (b"c", b"33")

        cursor.destroy()
finally:
    hse.fini()
