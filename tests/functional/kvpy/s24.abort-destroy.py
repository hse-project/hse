#!/usr/bin/env python3

import sys
from hse import Kvdb, Params

init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs24")
p = Params()
p.set(key="kvs.transactions_enable", value="1")
kvs = kvdb.kvs_open("kvs24", params=p)

txn = kvdb.transaction()
txn.begin()
cursor = kvs.cursor(txn=txn, bind_txn=True)
txn.abort()
cursor.destroy()

kvs.close()
kvdb.close()
fini()
