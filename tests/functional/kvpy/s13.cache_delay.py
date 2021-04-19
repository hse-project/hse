#!/usr/bin/env python3

import sys
import hse


hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs13")
    kvs = kvdb.kvs_open("kvs13")

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
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs13")
        kvdb.close()

hse.fini()
