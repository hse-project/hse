#!/usr/bin/env python3

from contextlib import ExitStack
from typing import List

import hse

from utility import lifecycle


def check_keys(cursor: hse.Cursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "nostale").rparams("transactions_enable=1")
        kvs = stack.enter_context(kvs_ctx)

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
        cursor1 = kvs.cursor(txn=txn1, flags=hse.CursorFlag.BIND_TXN)
        cursor2 = kvs.cursor(txn=txn2, flags=hse.CursorFlag.BIND_TXN)
        cursor3 = kvs.cursor(
            txn=txn3, flags=hse.CursorFlag.BIND_TXN | hse.CursorFlag.STATIC_VIEW
        )

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
finally:
    hse.fini()
