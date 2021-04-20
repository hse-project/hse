#!/usr/bin/env python3

import sys
from hse import Kvdb, Params

init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs22")
p = Params()
p.set(key="kvs.transactions_enable", value="1")
kvs = kvdb.kvs_open("kvs22", params=p)

with kvdb.transaction() as txn:
    kvs.put(b"a", b"1", txn=txn)
    kvs.put(b"b", b"2", txn=txn)
    kvs.put(b"c", b"3", txn=txn)

with kvdb.transaction() as txn:
    txcursor = kvs.cursor(txn=txn, bind_txn=True)
    txcursor.seek(b"a")
    kvs.delete(b"a", txn=txn)

with kvdb.transaction() as txn:
    kvs.put(b"a", b"11", txn=txn)

with kvdb.transaction() as txn:
    txcursor.update(bind_txn=True, txn=txn)
    txcursor.seek(b"a")
    kv = txcursor.read()
    assert kv == (b"a", b"11")

    txcursor.destroy()

kvs.close()
kvdb.close()
fini()
