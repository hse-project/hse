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
        with util.create_kvs(kvdb, "sfx_test_cn", p) as kvs:
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

            cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
            assert cnt == hse_exp.KvsPfxProbeCnt.MUL
            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abd")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbdXX", b"42"]

            kvs.put(b"AbdXX", b"43")
            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abd")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbdXX", b"43"]

            kvs.prefix_delete(b"A")
            kvs.put(b"AbeGarbageXY", b"45")
            kvdb.sync()

            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"AbeGarbage")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbeGarbageXY", b"45"]

            kvs.prefix_delete(b"A")
            kvs.put(b"AbeGarbageXZ", b"46")
            kvdb.sync()

            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"AbeGarbage")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbeGarbageXZ", b"46"]
finally:
    hse.fini()
