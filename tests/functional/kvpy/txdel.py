#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "txdel").rparams("transactions_enable=1")
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"pfx.a", b"1", txn=txn)
            kvs.put(b"pfx.b", b"2", txn=txn)
            kvs.put(b"pfx.c", b"3", txn=txn)

        with kvdb.transaction() as txn:
            with kvs.cursor(b"pfx", txn=txn, flags=hse.CursorFlag.BIND_TXN) as cur:
                kv = cur.read()
                assert kv == (b"pfx.a", b"1")
                kv = cur.read()
                assert kv == (b"pfx.b", b"2")
                kv = cur.read()
                assert kv == (b"pfx.c", b"3")
                cur.read()
                assert cur.eof

        with kvdb.transaction() as txn:
            kvs.delete(b"pfx.c", txn=txn)

        with kvdb.transaction() as txn:
            with kvs.cursor(b"pfx", txn=txn, flags=hse.CursorFlag.BIND_TXN) as cur:
                kv = cur.read()
                assert kv == (b"pfx.a", b"1")
                kv = cur.read()
                assert kv == (b"pfx.b", b"2")
                cur.read()
                assert cur.eof
finally:
    hse.fini()
