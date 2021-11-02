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
    kvs.put("a", "1")
    kvs.put("b", "2")
    kvs.put("c", "3")
    kvs.put("d", "4")
    kvs.put("e", "5")
    kvs.put("f", "6")
    kvs.put("g", "7")
    kvs.put("h", "8")

    cursor = kvs.cursor()
    check_keys(cursor, ["a", "b", "c", "d", "e", "f", "g", "h"])

    kvs.delete("a")
    kvs.delete("b")
    kvs.delete("c")
    kvs.delete("d")
    kvs.delete("e")

    cursor.update_view()
    cursor.seek("a")
    kv = cursor.read()
    assert kv == ("f", "6")
    cursor.seek("a")
    kv = cursor.read()
    assert kv == ("f", "6")

    kvs.delete("f")
    cursor.update_view()
    cursor.seek("a")
    kv = cursor.read()
    assert kv == ("g", "7")
    cursor.seek("a")
    kv = cursor.read()
    assert kv == ("g", "7")

    kvs.put("c", "33")
    cursor.update_view()
    cursor.seek("a")
    kv = cursor.read()
    assert kv == ("c", "33")

    cursor.destroy()

'''
Perform the operations as done by mongo when it's running range delete after having moved chunks
across shards
'''
def tombspan_test(kvdb: hse.Kvdb, kvs: hse.Kvs):
    numkeys = 100 * 1000
    half = int(numkeys / 2)
    synccnt = numkeys / 20

    key = f"ab{99999:0>12}"
    kvs.put(key, "base")
    for i in range(half, numkeys):
        key = f"ab{i:0>12}"
        kvs.delete(key)
        if i % synccnt == 0:
            kvdb.sync()

    for i in range(half):
        key = f"ab{i:0>12}"
        kvs.put(key, "val")

    k = "a"
    for i in range(half):
        with kvs.cursor(filt="a") as c:
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
