#!/usr/bin/env python3

from contextlib import ExitStack
from hse2 import hse

from utility import lifecycle, cli


hse.init(cli.HOME)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "txn_seek_del_put_next").rparams(
            "transactions_enable=1"
        )
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"a", b"1", txn=txn)
            kvs.put(b"b", b"2", txn=txn)
            kvs.put(b"c", b"3", txn=txn)

        with kvdb.transaction() as txn:
            txcursor = kvs.cursor(txn=txn)
            txcursor.seek(b"a")
            kvs.delete(b"a", txn=txn)

        with kvdb.transaction() as txn:
            kvs.put(b"a", b"11", txn=txn)

        with kvdb.transaction() as txn:
            txcursor.seek(b"a")
            kv = txcursor.read()
            assert kv == (b"a", b"1")

            txcursor.destroy()
finally:
    hse.fini()
