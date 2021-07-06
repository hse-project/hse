#!/usr/bin/env python3

from contextlib import ExitStack
from typing import List

from hse2 import hse

from utility import lifecycle


def check_keys(cursor: hse.KvsCursor, expected: List[bytes]):
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

        # Create a cursor for each txn
        cursor1 = kvs.cursor(txn=txn1)
        cursor2 = kvs.cursor(txn=txn2)

        # Add a few keys to each txn
        kvs.put(b"b1", b"21", txn=txn1)
        kvs.put(b"c1", b"31", txn=txn1)
        kvs.put(b"b2", b"21", txn=txn2)
        kvs.put(b"c2", b"31", txn=txn2)

        # Check that the cursors see all keys
        # Check that each cursor sees (b, 2) as the next kv pair when seeked to 'b'
        for c in [cursor1, cursor2]:
            assert 6 == sum(1 for _ in c.items())

            c.seek(b"b")
            kv = c.read()
            assert kv == (b"b", b"2")

        # Add a key to each txn
        kvs.put(b"d1", b"41", txn=txn1)
        kvs.put(b"d2", b"41", txn=txn2)

        # Commit txn1 and abort txn2
        txn1.commit()
        txn2.abort()

        # txn1 should see it's keys + original keys
        check_keys(cursor1, [b"b1", b"c", b"c1", b"d", b"d1"])

        # txn2 should see original keys
        check_keys(cursor2, [b"c", b"d"])

        cursor1.destroy()
        cursor2.destroy()
finally:
    hse.fini()
