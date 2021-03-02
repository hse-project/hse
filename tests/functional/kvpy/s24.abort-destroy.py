#!/usr/bin/env python3

import sys
from hse import Kvdb

Kvdb.init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs24")
kvs = kvdb.kvs_open("kvs24")

txn = kvdb.transaction()
txn.begin()
cursor = kvs.cursor(txn=txn, bind_txn=True)
txn.abort()
cursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
