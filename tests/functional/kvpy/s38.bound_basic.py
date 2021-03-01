#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

kvdb = hse.Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs1")
kvs = kvdb.kvs_open("kvs1")

'''
txn=None
kvs.put(b'ab0', b'1', txn=txn)
kvs.put(b'ab1', b'1', txn=txn)
kvs.put(b'ab2', b'1', txn=txn)
cursor = kvs.cursor()

for k, v in cursor.items():
    print(f'{k}: {v}')

cursor.update()
cursor.seek(b'0')
for k, v in cursor.items():
    print(f'{k}: {v}')
'''








txn = kvdb.transaction()
txn2 = kvdb.transaction()
kvs.put(b'ab0', b'1')
kvs.put(b'ab1', b'1')
txn.begin()
txn2.begin()
kvs.put(b'ab1', b'4', txn=txn2)
txn2.abort()

kvs.put(b'ab1', b'2', txn=txn)
kvs.put(b'ab2', b'2', txn=txn)
kvs.put(b'ab3', b'2', txn=txn)
cursor = kvs.cursor(bind_txn=True, txn=txn)
print('Before')

for k, v in cursor.items():
    print(f'{k}: {v}')

cursor.update(bind_txn=True, txn=txn)

txn.abort()
print('After')
cursor.seek(b'0')
for k, v in cursor.items():
    print(f'{k}: {v}')

cursor.destroy()
kvs.close()
kvdb.close()

hse.Kvdb.fini()
