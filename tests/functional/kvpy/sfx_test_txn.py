#!/usr/bin/env python3

from contextlib import ExitStack
from hse2 import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("dur_enable=0")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = (
            lifecycle.KvsContext(kvdb, "sfx_test_txn")
            .cparams("pfx_len=1", "sfx_len=2")
            .rparams("transactions_enable=1")
        )

        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"AbcXX", b"1", txn=txn)
            kvs.put(b"AbdXX", b"1", txn=txn)
            kvs.put(b"AbdXX", b"2", txn=txn)

        txn = kvdb.transaction()
        txn.begin()

        kvdb.sync(flags=hse.SyncFlag.ASYNC)
        with kvdb.transaction() as t:
            kvs.put(b"AbcXY", b"2", txn=t)

        cnt, *kv = kvs.prefix_probe(b"Abc", txn=txn)
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"1"]

        kvdb.sync(flags=hse.SyncFlag.ASYNC)
        kvs.put(b"AbcXZ", b"3", txn=txn)
        cnt, *kv = kvs.prefix_probe(b"Abc", txn=txn)  # inside txn
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcXZ", b"3"]
        with kvdb.transaction() as t:
            cnt, *kv = kvs.prefix_probe(b"Abc", txn=t)  # outside txn
            assert cnt == hse.KvsPfxProbeCnt.MUL
            assert kv == [b"AbcXY", b"2"]

        txn.commit()

        cnt, *kv = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcXZ", b"3"]
finally:
    hse.fini()
