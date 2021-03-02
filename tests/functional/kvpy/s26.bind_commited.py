#!/usr/bin/env python3

import sys
from hse import Kvdb

Kvdb.init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs26")
kvs = kvdb.kvs_open("kvs26")

txn = kvdb.transaction()
txn.begin()

txcursor = kvs.cursor(txn=txn, bind_txn=True)
kvs.put(b"a", b"1", txn=txn)
kvs.put(b"b", b"2", txn=txn)
kvs.put(b"c", b"3", txn=txn)
kv = txcursor.read()
assert kv == (b"a", b"1")

txn.commit()
txn.begin()
txcursor.update(txn=txn, bind_txn=True)
kvs.put(b"a", b"12", txn=txn)
kvs.put(b"b", b"22", txn=txn)
kvs.put(b"c", b"32", txn=txn)

kv = txcursor.read()
assert kv == (b"b", b"22")
kv = txcursor.read()
assert kv == (b"c", b"32")

cursor = kvs.cursor()
kv = cursor.read()
assert kv == (b"a", b"1")
kv = cursor.read()
assert kv == (b"b", b"2")
kv = cursor.read()
assert kv == (b"c", b"3")
cursor.read()
assert cursor.eof
cursor.destroy()

txcursor.seek(b"0")
kv = txcursor.read()
assert kv == (b"a", b"12")
kv = txcursor.read()
assert kv == (b"b", b"22")
kv = txcursor.read()
assert kv == (b"c", b"32")
txcursor.read()
assert txcursor.eof

txcursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
