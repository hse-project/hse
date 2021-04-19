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
kvdb.kvs_make("kvs31", params=p)
kvs = kvdb.kvs_open("kvs31", params=p)

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

kvs.close()
kvdb.close()
fini()
