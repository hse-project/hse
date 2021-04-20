#!/usr/bin/env python3

import sys
from typing import List
from hse import init, fini, Kvdb, Cursor, Params


def check_keys(cursor: Cursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs18")
p = Params()
p.set(key="kvs.transactions_enable", value="1")
kvs = kvdb.kvs_open("kvs18", params=p)

# Insert some keys
with kvdb.transaction() as txn:
    kvs.put(b"a", b"1", txn=txn)
    kvs.put(b"b", b"2", txn=txn)
    kvs.put(b"c", b"3", txn=txn)
    kvs.put(b"d", b"4", txn=txn)

# Begin three transactions
txn1 = kvdb.transaction()
txn1.begin()
txn2 = kvdb.transaction()
txn2.begin()
txn3 = kvdb.transaction()
txn3.begin()

# Create a bound cursor over each txn
cursor1 = kvs.cursor(txn=txn1, bind_txn=True)
cursor2 = kvs.cursor(txn=txn2, bind_txn=True)
cursor3 = kvs.cursor(txn=txn3, bind_txn=True, static_view=True)

# Add a few keys to each txn
kvs.put(b"b1", b"21", txn=txn1)
kvs.put(b"c1", b"31", txn=txn1)
kvs.put(b"b2", b"21", txn=txn2)
kvs.put(b"c2", b"31", txn=txn2)
kvs.put(b"b3", b"21", txn=txn3)
kvs.put(b"c3", b"31", txn=txn3)

# Check that the cursors see all keys
# Check that each cursor sees (b, 2) as the next kv pair when seeked to 'b'
for c in [cursor1, cursor2, cursor3]:
    assert 6 == sum(1 for _ in c.items())

    c.seek(b"b")
    kv = c.read()
    assert kv == (b"b", b"2")

# Add a key to each txn
kvs.put(b"d1", b"41", txn=txn1)
kvs.put(b"d2", b"41", txn=txn2)
kvs.put(b"d3", b"41", txn=txn3)

# Commit txn1 and abort the others.
txn1.commit()
txn2.abort()
txn3.abort()  # cursor3 should fall back on what was txn3's view

# Both cursors should be positioned to current kvs view
check_keys(cursor1, [b"b1", b"c", b"c1", b"d", b"d1"])
check_keys(cursor2, [b"b1", b"c", b"c1", b"d", b"d1"])
check_keys(cursor3, [b"c", b"d"])

cursor1.destroy()
cursor2.destroy()
cursor3.destroy()

kvs.close()
kvdb.close()
fini()
