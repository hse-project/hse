#!/usr/bin/env python3

"""
This script tests the following (forward cursors only):
  1. Updated cursor reads newly inserted key right after its last read key.
  2. Updated cursor reads new key inserted past eof when cursor had reached eof
  3. A bound cursor passes case 1 and 2 without needing an update
"""

import sys
from hse import Kvdb, Params

Kvdb.init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs17")
p = Params()
p.set(key="kvs.enable_transactions", value="1")
kvs = kvdb.kvs_open("kvs17", params=p)

txn1 = kvdb.transaction()
txn1.begin()
kvs.put(b"a", b"1", txn=txn1)
kvs.put(b"b", b"2", txn=txn1)
kvs.put(b"c", b"3", txn=txn1)

# Read 2 keys using a cursor. Leave cursor pointing to 'c'
cursor = kvs.cursor(txn=txn1, bind_txn=True)
kv = cursor.read()
assert kv == (b"a", b"1")
kv = cursor.read()
assert kv == (b"b", b"2")

kvs.put(b"d", b"4", txn=txn1)
cursor.update(txn=txn1, bind_txn=True)
kv = cursor.read()
assert kv == (b"c", b"3")
kv = cursor.read()
assert kv == (b"d", b"4")
cursor.read()
assert cursor.eof
txn1.commit()

with kvdb.transaction() as txn:
    kvs.put(b"a", b"11", txn=txn)
    kvs.put(b"b", b"22", txn=txn)
    kvs.put(b"d", b"44", txn=txn)

    txcursor = kvs.cursor(txn=txn, bind_txn=True)
    kv = txcursor.read()
    assert kv == (b"a", b"11")
    kv = txcursor.read()
    assert kv == (b"b", b"22")

    # Put key 'c', cursor should see it next without
    # needing an update (because it's bound)
    kvs.put(b"c", b"33", txn=txn)
    kv = txcursor.read()
    assert kv == (b"c", b"33")

    kv = txcursor.read()
    assert kv == (b"d", b"44")

    cursor.read()
    assert cursor.eof

    # With cursor at eof, insert key past last rea: 'e'.
    # Cursor should see it next without needing an update
    kvs.put(b"e", b"55", txn=txn)
    kv = txcursor.read()
    assert kv == (b"e", b"55")

    cursor.read()
    assert cursor.eof

    txcursor.seek(b"c")
    kv = txcursor.read()
    assert kv == (b"c", b"33")

    # After txn aborts, txcursor should fall back to the txn's view.
    # But current position.
    txn.abort()
    kv = txcursor.read()
    assert kv == (b"d", b"4")

    txcursor.destroy()

txn1.begin()
kvs.put(b"e", b"5", txn=txn1)
print('hello')
cursor.update(txn=txn1, bind_txn=True)
kv = cursor.read()
print(kv)
assert kv == (b"e", b"5")

cursor.seek(b"d")
kv = cursor.read()
assert kv == (b"d", b"4")
kv = cursor.read()
assert kv == (b"e", b"5")
cursor.read()
assert cursor.eof
cursor.read()
assert cursor.eof

cursor.destroy()
txn1.commit()

# Count keys in kvs
txn1.begin()
with kvs.cursor(txn=txn1, bind_txn=True) as c:
    cnt = 0
    c.read()
    while not c.eof:
        cnt = cnt + 1
        c.read()

    assert cnt == 5
txn1.commit()

# Insert before update + read
txn1.begin()
kvs.put(b"q", b"1", txn=txn1)
kvs.put(b"r", b"1", txn=txn1)
kvs.put(b"t", b"1", txn=txn1)

cursor = kvs.cursor(txn=txn1, bind_txn=True)
cursor.seek(b"q")
kv = cursor.read()
assert kv == (b"q", b"1")
kv = cursor.read()
assert kv == (b"r", b"1")
txn1.commit()

txn1.begin()
kvs.put(b"s", b"1", txn=txn1)
cursor.update(txn=txn1, bind_txn=True)
kv = cursor.read()
assert kv == (b"s", b"1")
kv = cursor.read()
assert kv == (b"t", b"1")
cursor.read()
assert cursor.eof

cursor.destroy()
txn1.commit()

kvs.close()
kvdb.close()
Kvdb.fini()
