#!/usr/bin/env python3

import sys
from hse import Kvdb

Kvdb.init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs22")
kvs = kvdb.kvs_open("kvs22")

txn = kvdb.transaction()
txn.begin()

kvs.put(b"a", b"1", txn=txn)
kvs.put(b"b", b"2", txn=txn)
kvs.put(b"c", b"3", txn=txn)
txn.commit()

txn.begin()
txcursor = kvs.cursor(txn=txn, bind_txn=True)
txcursor.seek(b"a")
kvs.delete(b"a", txn=txn)
txn.commit()

txn.begin()
kvs.put(b"a", b"11", txn=txn)
txn.commit()

txcursor.update()
txcursor.seek(b"a")
kv = txcursor.read()
assert kv == (b"a", b"11")

txcursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
