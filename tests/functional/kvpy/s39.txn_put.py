#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

kvdb = hse.Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs1")
kvs = kvdb.kvs_open("kvs1")


txn = kvdb.transaction()

for i in range(1,5000):
    txn.begin()
    key = f'ab{i}'
    kvs.put(key.encode(), b'4', txn=txn)
    txn.commit()


kvs.close()
kvdb.close()

hse.Kvdb.fini()
