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
        kvs_ctx = lifecycle.KvsContext(kvdb, "update_views").rparams("transactions_enable=1")
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as t:
            kvs.put(b"a", b"1", txn=t)
            kvs.put(b"b", b"2", txn=t)
            kvs.put(b"d", b"4", txn=t)

        txn = kvdb.transaction()
        txn.begin()
        cursor = kvs.cursor(bind_txn=True, txn=txn)

        with kvdb.transaction() as t:
            kvs.put(b"f", b"6", txn=t)

        check_keys(cursor, [b"a", b"b", b"d"])

        txn.abort()
        txn.begin()
        cursor.update(bind_txn=True, txn=txn)  # cursor should now see key 'f'
        check_keys(cursor, [b"f"])

        txn1 = kvdb.transaction()
        txn1.begin()
        with kvdb.transaction() as t:
            kvs.put(b"c", b"3", txn=t)
        kvs.put(b"x", b"1", txn=txn1)

        txn2 = kvdb.transaction()
        txn2.begin()
        with kvdb.transaction() as t:
            kvs.put(b"e", b"5", txn=t)
        kvs.put(b"y", b"2", txn=txn2)

        cursor.read()
        assert cursor.eof

        txn.abort()
        txn.begin()
        cursor.update(bind_txn=True, txn=txn)
        cursor.seek(b"c")

        # Update after seek
        cursor.update(txn=txn1, bind_txn=True)
        kv = cursor.read()
        assert kv == (b"d", b"4")
        cursor.seek(b"c")  # positions cursor at 'd'

        with kvdb.transaction() as t:
            cursor.update(txn=t, bind_txn=True)  # Unbind cursor from txn
        kv = cursor.read()
        assert kv == (b"d", b"4")

        cursor.update(txn=txn1, bind_txn=True)
        cursor.update(txn=txn2, bind_txn=True)
        kv = cursor.read()
        assert kv == (b"f", b"6")
        kv = cursor.read()
        assert kv == (b"y", b"2")

        txn2.abort()
        cursor.seek(b"e")
        check_keys(cursor, [b"e", b"f"])

        cursor.update(txn=txn1, bind_txn=True)
        with kvdb.transaction() as t:
            kvs.put(b"g", b"7", txn=t)
        txn1.commit()

        check_keys(cursor, [b"g", b"x"])

        cursor.destroy()
finally:
    hse.fini()
