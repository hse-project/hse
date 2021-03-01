#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs16-1")
    kvdb.kvs_make("kvs16-2")
    kvs1 = kvdb.kvs_open("kvs16-1")
    kvs2 = kvdb.kvs_open("kvs16-2")

    kvs1.put(b"a", b"1")
    kvs1.put(b"b", b"1")
    kvs1.put(b"c", b"1")

    kvs2.put(b"a", b"2")
    kvs2.put(b"b", b"2")
    kvs2.put(b"c", b"2")

    with kvdb.transaction() as txn:
        cursor = kvs1.cursor(bind_txn=True, txn=txn)

        kv = cursor.read()
        assert kv == (b"a", b"1")
        kv = cursor.read()
        assert kv == (b"b", b"1")
        kv = cursor.read()
        assert kv == (b"c", b"1")
        cursor.read()
        assert cursor.eof

        kvs1.put(b"d", b"1", txn=txn)
        cursor.seek(b"d")
        cursor.update(bind_txn=True, txn=txn)

        cursor.seek(b"d")
        kv = cursor.read()
        assert kv == (b"d", b"1")

        txn.abort()
        cursor.seek(b"a")
        try:
            cursor.read()
            assert False
        except:
            pass

        cursor.destroy()

    txn = kvdb.transaction()
    txn.begin()
    kvs2.put(b"d", b"2", txn=txn)

    cursor1 = kvs2.cursor(bind_txn=True, txn=txn)
    cursor1.seek(b"d")
    kv = cursor1.read()
    assert kv == (b"d", b"2")
    cursor1.read()
    assert cursor1.eof
    txn.commit()

    cursor2 = kvs2.cursor()
    for k, v in cursor2.items():
        assert v == b"2"
    try:
        cursor1.read()
        assert False
    except:
        pass
    cursor1.destroy()
    cursor2.destroy()
finally:
    if kvs1:
        kvs1.close()
    if kvs2:
        kvs2.close()
    if kvdb:
        kvdb.kvs_drop("kvs16-1")
        kvdb.kvs_drop("kvs16-2")
        kvdb.close()

hse.Kvdb.fini()
