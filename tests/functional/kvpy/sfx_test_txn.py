#!/usr/bin/env python3

from contextlib import ExitStack
import hse
from hse import experimental as hse_exp

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

        kvdb.flush()
        with kvdb.transaction() as t:
            kvs.put(b"AbcXY", b"2", txn=t)

        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc", txn=txn)
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"1"]

        kvdb.flush()
        kvs.put(b"AbcXZ", b"3", txn=txn)
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc", txn=txn)  # inside txn
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcXZ", b"3"]
        with kvdb.transaction() as t:
            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc", txn=t)  # outside txn
            assert cnt == hse_exp.KvsPfxProbeCnt.MUL
            assert kv == [b"AbcXY", b"2"]

        txn.commit()

        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcXZ", b"3"]
finally:
    hse.fini()
