#!/usr/bin/env python3

import sys
from hse import Kvdb, Params
from hse import experimental as hse_exp

def add_keys(kvs, pfx, start, end):
    for k_id in range(start, end):
        key = f'{pfx}-{k_id:0>10}'
        kvs.put(key.encode(), b'val')

def verify_keys(kvs, pfx, start, end):
    with kvs.cursor(filt=pfx.encode()) as cur:
        assert sum(1 for _ in cur.items()) == end - start

    with kvs.cursor(filt=pfx.encode()) as cur:
        k_id = start
        for (k, v) in cur.items():
            expected = f'{pfx}-{k_id:0>10}'.encode()
            assert k == expected
            assert k_id < end
            k_id = k_id + 1

Kvdb.init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")
p.set(key="kvs.pfx_len", value="2")

kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs32", params=p)
kvs = kvdb.kvs_open("kvs32", params=p)

num_keys = 1000 * 1000

kvs.prefix_delete(b'AA')

add_keys(kvs=kvs, pfx='AA', start=0, end=num_keys)
add_keys(kvs=kvs, pfx='AB', start=0, end=num_keys)
add_keys(kvs=kvs, pfx='AC', start=0, end=num_keys)
add_keys(kvs=kvs, pfx='AD', start=0, end=num_keys)

kvdb.sync()

kvs.prefix_delete(b'AB')

add_keys(kvs=kvs, pfx='AA', start=num_keys, end=2*num_keys)
add_keys(kvs=kvs, pfx='AB', start=num_keys, end=2*num_keys)
add_keys(kvs=kvs, pfx='AC', start=num_keys, end=2*num_keys)
add_keys(kvs=kvs, pfx='AD', start=num_keys, end=2*num_keys)

kvs.prefix_delete(b'AC')

verify_keys(kvs=kvs, pfx='AA', start=0, end=2*num_keys)
verify_keys(kvs=kvs, pfx='AB', start=num_keys, end=2*num_keys)
verify_keys(kvs=kvs, pfx='AC', start=0, end=0)
verify_keys(kvs=kvs, pfx='AD', start=0, end=2*num_keys)

kvs.close()
kvdb.close()
Kvdb.fini()
