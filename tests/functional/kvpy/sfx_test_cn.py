#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("dur_enable=0")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_cn").cparams(
            "pfx_len=1", "sfx_len=2"
        )
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbcXX", b"42")
        kvs.put(b"AbdXX", b"42")
        kvdb.sync()

        kvs.put(b"AbcXX", b"44")
        kvs.put(b"AbcXY", b"43")
        kvs.put(b"AbeGarbageXY", b"43")
        kvs.put(b"BcdXX", b"42")
        kvdb.sync()

        kvs.put(b"AbaXX", b"42")
        kvs.put(b"AbeGarbageXY", b"44")
        kvdb.sync()

        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        cnt, *kv = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert kv == [b"AbdXX", b"42"]

        kvs.put(b"AbdXX", b"43")
        cnt, *kv = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert kv == [b"AbdXX", b"43"]

        kvs.prefix_delete(b"A")
        kvs.put(b"AbeGarbageXY", b"45")
        kvdb.sync()

        cnt, *kv = kvs.prefix_probe(b"AbeGarbage")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert kv == [b"AbeGarbageXY", b"45"]

        kvs.prefix_delete(b"A")
        kvs.put(b"AbeGarbageXZ", b"46")
        kvdb.sync()

        cnt, *kv = kvs.prefix_probe(b"AbeGarbage")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert kv == [b"AbeGarbageXZ", b"46"]
finally:
    hse.fini()
