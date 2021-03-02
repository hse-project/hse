#!/usr/bin/env python3

import sys
from typing import List
from hse import Kvdb, Cursor


def check_keys(cursor: Cursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


Kvdb.init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs20")
kvs = kvdb.kvs_open("kvs20")

kvs.put(b"a", b"1")
kvs.put(b"b", b"2")
kvs.put(b"d", b"4")

cursor = kvs.cursor()
kvs.put(b"f", b"6")

check_keys(cursor, [b"a", b"b", b"d"])

cursor.update()  # cursor should now see key 'f'
check_keys(cursor, [b"f"])

txn1 = kvdb.transaction()
txn1.begin()
kvs.put(b"c", b"3")
kvs.put(b"x", b"1", txn=txn1)

txn2 = kvdb.transaction()
txn2.begin()
kvs.put(b"e", b"5")
kvs.put(b"y", b"2", txn=txn2)

cursor.read()
assert cursor.eof

cursor.update()
cursor.seek(b"c")

# Update after seek
cursor.update(txn=txn1, bind_txn=True)
kv = cursor.read()
assert kv == (b"d", b"4")
cursor.seek(b"c")  # positions cursor at 'd'

cursor.update()  # Unbind cursor from txn
kv = cursor.read()
assert kv == (b"d", b"4")

cursor.update(txn=txn1, bind_txn=True)
cursor.update(txn=txn2, bind_txn=True)
kv = cursor.read()
assert kv == (b"f", b"6")
kv = cursor.read()
assert kv == (b"y", b"2")

txn2.abort()
cursor.seek(b"e")
check_keys(cursor, [b"e", b"f"])

cursor.update(txn=txn1, bind_txn=True)
kvs.put(b"g", b"7")
txn1.commit()

check_keys(cursor, [b"g", b"x"])

cursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
