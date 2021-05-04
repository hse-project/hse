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
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_tomb").cparams(
            "pfx_len=1", "sfx_len=2"
        )
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbcXX", b"1")
        kvs.put(b"AbdXX", b"1")
        kvs.put(b"AbdXY", b"2")
        kvdb.flush()

        cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abd")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL

        kvs.delete(b"AbdXY")
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abd")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbdXX", b"1"]
        kvdb.sync()
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abd")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbdXX", b"1"]

        # Multiple tombs
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"1"]

        kvs.prefix_delete(b"A")

        kvs.put(b"AbcX1", b"1")
        kvs.put(b"AbcX2", b"1")
        kvs.put(b"AbcX3", b"1")
        kvs.put(b"AbcX4", b"1")
        kvs.put(b"AbcX5", b"1")
        kvs.put(b"AbcX6", b"1")
        kvdb.sync()
        kvs.put(b"AbcX7", b"1")
        kvs.put(b"AbcX8", b"1")
        kvs.put(b"AbcX9", b"1")

        cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL

        kvs.delete(b"AbcX1")
        kvs.delete(b"AbcX2")
        kvs.delete(b"AbcX3")
        kvs.delete(b"AbcX7")
        kvs.delete(b"AbcX8")

        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcX9", b"1"]

        """
        [HSE_REVISIT] - why is this commented out? @gaurav

        txn = kvdb.transaction()
        txn.begin()
        kvs.delete(b"AbcX9", txn=txn)
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc", txn=txn)
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcX4", b"1"]
        txn.commit()
        """

        kvs.delete(b"AbcX9")

        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcX4", b"1"]

        kvdb.sync()
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL
        assert kv == [b"AbcX4", b"1"]
finally:
    hse.fini()
