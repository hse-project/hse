#!/usr/bin/env python3
from typing import List

import hse

import util


def check_keys(cursor: hse.Cursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "update_seek", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")
            kvs.put(b"c", b"3")
            kvs.put(b"d", b"4")

            cursor = kvs.cursor()
            cursor.seek(b"c")
            check_keys(cursor, [b"c", b"d"])

            cursor.seek(b"c")
            cursor.update()
            check_keys(cursor, [b"c", b"d"])
            cursor.destroy()

            kvdb.sync()
            cursor = kvs.cursor()
            cursor.seek(b"c")
            check_keys(cursor, [b"c", b"d"])

            cursor.seek(b"c")
            cursor.update()
            check_keys(cursor, [b"c", b"d"])
            cursor.destroy()
finally:
    hse.fini()
