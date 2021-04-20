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
kvdb.kvs_make("kvs28")
kvs = kvdb.kvs_open("kvs28")

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

cursor.update()
cursor.seek(b"a")
kv = cursor.read()
assert kv == (b"f", b"6")
cursor.seek(b"a")
kv = cursor.read()
assert kv == (b"f", b"6")

kvs.delete(b"f")
cursor.update()
cursor.seek(b"a")
kv = cursor.read()
assert kv == (b"g", b"7")
cursor.seek(b"a")
kv = cursor.read()
assert kv == (b"g", b"7")

kvs.put(b"c", b"33")
cursor.update()
cursor.seek(b"a")
kv = cursor.read()
assert kv == (b"c", b"33")

cursor.destroy()

kvs.close()
kvdb.close()
fini()
