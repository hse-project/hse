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
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_c0cn").cparams(
            "pfx_len=1", "sfx_len=2"
        )
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbaXX", b"42")
        kvs.put(b"AbcXX", b"42")
        kvs.put(b"AbdXX", b"42")
        kvdb.sync()

        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"42"]

        kvs.put(b"AbcXY", b"42")  # second (multiple) in c0
        cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.MUL

        kvs.prefix_delete(b"A")
        cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ZERO
        kvdb.sync()
        cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ZERO

        kvs.put(b"AbcXX", b"44")
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"44"]
        kvdb.sync()
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"44"]

        # duplicate in c0 and cn
        kvs.put(b"AbcXX", b"45")
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"45"]
        kvdb.sync()
        cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
        assert cnt == hse_exp.KvsPfxProbeCnt.ONE
        assert kv == [b"AbcXX", b"45"]
finally:
    hse.fini()
