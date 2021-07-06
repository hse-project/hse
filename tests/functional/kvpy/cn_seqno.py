#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("dur_enable=0")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "cn_seqno").rparams(
            "transactions_enable=1"
        )
        kvs = stack.enter_context(kvs_ctx)

        txn = kvdb.transaction()
        txn.begin()

        with kvdb.transaction() as t:
            kvs.put(b"a", b"1", txn=t)

        kvdb.sync()

        txcursor = kvs.cursor(txn=txn)
        txcursor.read()
        assert txcursor.eof

        txn.abort()
        txcursor.seek(b"0")
        kv = txcursor.read()
        assert txcursor.eof

        txcursor.destroy()
finally:
    hse.fini()
