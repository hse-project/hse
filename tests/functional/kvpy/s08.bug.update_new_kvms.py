#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs8")
    kvs = kvdb.kvs_open("kvs8")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")

    cursor = kvs.cursor()
    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    cursor.read()
    assert cursor.eof

    kvdb.flush()

    kvs.put(b"c", b"3")
    kvdb.flush()

    kvs.put(b"d", b"4")
    kvdb.flush()

    kvs.put(b"e", b"5")
    kvdb.flush()

    kvs.put(b"f", b"6")

    with kvdb.transaction() as txn:
        kvs.put(b"c", b"3")

    cursor.update()
    cursor.seek(b"0x00")

    assert sum(1 for _ in cursor.items()) == 6

    cursor.destroy()
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs8")
        kvdb.close()

hse.Kvdb.fini()
