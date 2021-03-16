#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs15")
    p = hse.Params()
    p.set(key="kvs.enable_transactions", value="1")
    kvs = kvdb.kvs_open("kvs15", params=p)

    with kvdb.transaction() as txn:
        kvs.put(b"a", b"1", txn=txn)
        kvs.put(b"b", b"2", txn=txn)
        kvs.put(b"c", b"3", txn=txn)

    txn1 = kvdb.transaction()
    txn1.begin()

    with kvdb.transaction() as t:
        kvs.put(b"d", b"4", txn=t)

    cursor = kvs.cursor(txn=txn1)

    kvs.put(b"a", b"5", txn=txn1)

    kv = cursor.read()
    assert kv == (b"a", b"1")
    kv = cursor.read()
    assert kv == (b"b", b"2")
    kv = cursor.read()
    assert kv == (b"c", b"3")
    cursor.read()
    assert cursor.eof

    txn2 = kvdb.transaction()
    txn2.begin()
    cursor.update(txn=txn2)
    cursor.seek(b"d")

    kv = cursor.read()
    print(kv)
    assert kv == (b"d", b"4")
    cursor.read()
    assert cursor.eof

    txn1.commit()
    txn2.commit()

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
