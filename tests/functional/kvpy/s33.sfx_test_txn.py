#!/usr/bin/env python3

import sys
from hse import Kvdb, Params
from hse import experimental as hse_exp

Kvdb.init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")
p.set(key="kvs.pfx_len", value="1")
p.set(key="kvs.sfx_len", value="2")
p.set(key="kvs.transactions_enable", value="1")

kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs33", params=p)
kvs = kvdb.kvs_open("kvs33", params=p)


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

kvs.close()
kvdb.close()
Kvdb.fini()
