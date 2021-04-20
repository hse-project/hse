#!/usr/bin/env python3

import sys
from typing import List
from hse import init, fini, Kvdb, Cursor


def check_keys(cursor: Cursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs21")
kvs = kvdb.kvs_open("kvs21")

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

kvs.close()
kvdb.close()
fini()
