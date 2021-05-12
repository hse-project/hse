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
        with util.create_kvs(kvdb, "sfx_test_c0", p) as kvs:
            kvs.put(b"AbaXX", b"42")
            kvs.put(b"AbcXX", b"42")
            kvs.put(b"AbdXX", b"42")

            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbcXX", b"42"]

            kvdb.flush()
            kvs.put(b"AbcXX", b"43")  # duplicate

            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbcXX", b"43"]

            kvs.put(b"AbcXY", b"42")  # multiple
            cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
            assert cnt == hse_exp.KvsPfxProbeCnt.MUL
            kvs.put(b"AbcXZ", b"42")  # multiple
            cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"Abc")
            assert cnt == hse_exp.KvsPfxProbeCnt.MUL

            kvs.prefix_delete(b"A")
            kvs.put(b"AbcXZ", b"44")
            cnt, *kv = hse_exp.kvs_prefix_probe(kvs, b"Abc")
            assert cnt == hse_exp.KvsPfxProbeCnt.ONE
            assert kv == [b"AbcXZ", b"44"]
finally:
    hse.fini()
