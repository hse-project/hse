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
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "sfx_test_txn", p) as kvs:
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
