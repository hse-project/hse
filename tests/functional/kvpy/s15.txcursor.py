#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs15")
    kvs = kvdb.kvs_open("kvs15")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")
    kvs.put(b"c", b"3")

    txn = kvdb.transaction()
    txn.begin()

    kvs.put(b"d", b"4")

    cursor = kvs.cursor(txn=txn)

    kvs.put(b"a", b"5", txn=txn)

    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    kv = cursor.read()
    assert kv == (b"c", b"3")
    cursor.read()
    assert cursor.eof

    cursor.update()
    cursor.seek(b"d")

    kv = cursor.read()
    assert kv == (b"d", b"4")
    cursor.read()
    assert cursor.eof

    txn.commit()

    cursor.update()
    cursor.seek(b"0")

    kv = cursor.read()
    assert kv == (b"a", b"5")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    kv = cursor.read()
    assert kv == (b"c", b"3")
    kv = cursor.read()
    assert kv == (b"d", b"4")
    cursor.read()
    assert cursor.eof

    cursor.destroy()
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs15")
        kvdb.close()

hse.Kvdb.fini()
