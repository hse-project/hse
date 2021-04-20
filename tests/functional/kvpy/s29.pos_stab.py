#!/usr/bin/env python3

import sys
from hse import init, fini, Kvdb, Params

init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest

# Test 1: Update after seek. Seek can be to an existing key or non-existent key
kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs29-1", params=p)
kvs = kvdb.kvs_open("kvs29-1", params=p)

kvs.put(b"a", b"1")
kvs.put(b"b", b"2")
kvs.put(b"d", b"4")
kvs.put(b"e", b"5")

cursor = kvs.cursor()

# seek to an existing key and update.
cursor.seek(b"b")
cursor.update()
kv = cursor.read()
assert kv == (b"b", b"2")

# seek to a non-existent key and update.
cursor.seek(b"c")
kvs.put(b"c", b"3")
cursor.update()

kv = cursor.read()
assert kv == (b"d", b"4")
kvs.close()

# Test 2: Read keys across c0/cn
p.set(key="kvs.pfx_len", value="2")
kvdb.kvs_make("kvs29-2", params=p)
kvs = kvdb.kvs_open("kvs29-2", params=p)

kvs.put(b"ab1", b"1")
kvdb.sync()
kvs.put(b"ab2", b"2")
kvdb.sync()

# Forward cursor
cursor = kvs.cursor(filt=b"ab")
kv = cursor.read()
assert kv == (b"ab1", b"1")

kvs.put(b"ab1", b"2")

cursor.update()
kv = cursor.read()
assert kv == (b"ab2", b"2")
cursor.read()
assert cursor.eof
cursor.destroy()

# Reverse cursor
cursor = kvs.cursor(filt=b"ab", reverse=True)
kv = cursor.read()
assert kv == (b"ab2", b"2")

kvs.put(b"ab2", b"3")

cursor.update(reverse=True)
kv = cursor.read()
assert kv == (b"ab1", b"2")
cursor.read()
assert cursor.eof
cursor.destroy()
kvs.close()

# Test 3: Read keys across c0/cn, with key update.
p.set(key="kvs.pfx_len", value="1")
p.set(key="kvs.transactions_enable", value="1")
kvdb.kvs_make("kvs29-3", params=p)
kvs = kvdb.kvs_open("kvs29-3", params=p)

with kvdb.transaction() as txn:
    kvs.put(b"a1a", b"1", txn=txn)
    kvs.put(b"a1b", b"2", txn=txn)
    kvs.put(b"a1c", b"3", txn=txn)
kvdb.sync()

with kvdb.transaction() as txn:
    kvs.put(b"a1b", b"4", txn=txn)

read_txn = kvdb.transaction()
read_txn.begin()
cursor = kvs.cursor(txn=read_txn, bind_txn=True)
cursor.seek(b"a1b")
kv = cursor.read()
assert kv == (b"a1b", b"4")

revcursor = kvs.cursor(reverse=True, txn=read_txn, bind_txn=True)
revcursor.seek(b"a1b")
kv = revcursor.read()
assert kv == (b"a1b", b"4")
read_txn.abort()

kvdb.sync()

txn = kvdb.transaction()
txn.begin()
cursor.update(txn=txn, bind_txn=True)
cursor.update(txn=txn, bind_txn=True)
cursor.update(txn=txn, bind_txn=True)
revcursor.update(txn=txn, bind_txn=True, reverse=True)
revcursor.update(txn=txn, bind_txn=True, reverse=True)
revcursor.update(txn=txn, bind_txn=True, reverse=True)

kv = cursor.read()
assert kv == (b"a1c", b"3")
kv = revcursor.read()
assert kv == (b"a1a", b"1")

cursor.destroy()
revcursor.destroy()

kvs.close()
kvdb.close()
fini()
