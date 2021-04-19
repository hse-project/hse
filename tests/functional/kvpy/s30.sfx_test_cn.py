#!/usr/bin/env python3

import sys
from hse import Kvdb, Params
from hse import experimental as hse_exp

init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")
p.set(key="kvs.pfx_len", value="1")
p.set(key="kvs.sfx_len", value="2")

kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs30", params=p)
kvs = kvdb.kvs_open("kvs30", params=p)

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

kvs.close()
kvdb.close()
fini()
