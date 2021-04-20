#!/usr/bin/env python3

import sys
import hse


hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs7")
    kvs = kvdb.kvs_open("kvs7")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")

    cursor = kvs.cursor()
    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    cursor.read()
    assert cursor.eof

    kvs.put(b"c", b"3")

    cursor.update()
    cursor.seek(b"0x00")

    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    kv = cursor.read()
    assert kv == (b"c", b"3")
    cursor.read()
    assert cursor.eof

    cursor.destroy()
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs7")
        kvdb.close()

hse.fini()
