#!/usr/bin/env python3

import sys
from hse import init, fini, Kvdb, Params
from hse import experimental as hse_exp

init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")
p.set(key="kvs.pfx_len", value="1")
p.set(key="kvs.sfx_len", value="2")

kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs32", params=p)
kvs = kvdb.kvs_open("kvs32", params=p)

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

kvs.close()
kvdb.close()
fini()
