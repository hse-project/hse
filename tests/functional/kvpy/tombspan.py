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

def test_basic(kvdb: hse.Kvdb, kvs: hse.Kvs):
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

'''
Perform the operations as done by mongo when it's running range delete after having moved chunks
across shards
'''
def tombspan_test(kvdb: hse.Kvdb, kvs: hse.Kvs):
    numkeys = 100 * 1000
    half = int(numkeys / 2)
    synccnt = numkeys / 20

    key = "ab{:0>12}".format(99999)
    kvs.put(key, "base")
    for i in range(half, numkeys):
        key = "ab{:0>12}".format(i)
        kvs.delete(key)
        if i % synccnt == 0:
            kvdb.sync()

    for i in range(half):
        key = "ab{:0>12}".format(i)
        kvs.put(key, "val")

    k = "ab"
    for i in range(half):
        with kvs.cursor(filt="ab") as c:
            c.seek(k)
            k, v = c.read()
            if not c.eof:
                kvs.delete(k)

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "tmobspan")

        with kvs_ctx as kvs:
            test_basic(kvdb, kvs)

        with kvs_ctx as kvs:
            tombspan_test(kvdb, kvs)
finally:
    hse.fini()
