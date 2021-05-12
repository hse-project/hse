#!/usr/bin/env python3
import hse
from hse import experimental as hse_exp

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvdb.dur_enable", value="0")
    p.set(key="kvs.pfx_len", value="1")
    p.set(key="kvs.sfx_len", value="2")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "sfx_test_c0cn", p) as kvs:
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
