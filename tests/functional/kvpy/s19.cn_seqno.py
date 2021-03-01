#!/usr/bin/env python3

import sys
from hse import Kvdb, Params

Kvdb.init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest

kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs19", params=p)
kvs = kvdb.kvs_open("kvs19", params=p)

txn = kvdb.transaction()
txn.begin()

kvs.put(b"a", b"1")
kvdb.sync()

txcursor = kvs.cursor(txn=txn, bind_txn=True)
txcursor.read()
assert txcursor.eof

txn.abort()
txcursor.seek(b"0")
kv = txcursor.read()
assert not txcursor.eof
assert kv == (b"a", b"1")

txcursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
