#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:

    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "bind_committed").rparams("transactions_enable=1")
        kvs = stack.enter_context(kvs_ctx)

        txn = kvdb.transaction()
        txn.begin()

        txcursor = kvs.cursor(txn=txn, flags=hse.CursorFlag.BIND_TXN)
        kvs.put(b"a", b"1", txn=txn)
        kvs.put(b"b", b"2", txn=txn)
        kvs.put(b"c", b"3", txn=txn)
        kv = txcursor.read()
        assert kv == (b"a", b"1")

        txn.commit()
        txn.begin()
        txcursor.update(txn=txn, flags=hse.CursorFlag.BIND_TXN)
        kvs.put(b"a", b"12", txn=txn)
        kvs.put(b"b", b"22", txn=txn)
        kvs.put(b"c", b"32", txn=txn)

        kv = txcursor.read()
        assert kv == (b"b", b"22")
        kv = txcursor.read()
        assert kv == (b"c", b"32")

        with kvdb.transaction() as t:
            cursor = kvs.cursor(txn=t, flags=hse.CursorFlag.BIND_TXN)
            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"2")
            kv = cursor.read()
            assert kv == (b"c", b"3")
            cursor.read()
            assert cursor.eof
            cursor.destroy()

        txcursor.seek(b"0")
        kv = txcursor.read()
        assert kv == (b"a", b"12")
        kv = txcursor.read()
        assert kv == (b"b", b"22")
        kv = txcursor.read()
        assert kv == (b"c", b"32")
        txcursor.read()
        assert txcursor.eof

        txcursor.destroy()
finally:
    hse.fini()
