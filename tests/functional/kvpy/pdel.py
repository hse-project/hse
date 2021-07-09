#!/usr/bin/env python3

from contextlib import ExitStack
from hse2 import hse

from utility import lifecycle


def add_keys(kvs: hse.Kvs, pfx: str, start: int, end: int):
    for k_id in range(start, end):
        key = f"{pfx}-{k_id:0>10}"
        kvs.put(key.encode(), b"val")


def verify_keys(kvs: hse.Kvs, pfx: str, start: int, end: int):
    with kvs.cursor(filt=pfx.encode()) as cur:
        assert sum(1 for _ in cur.items()) == end - start

    with kvs.cursor(filt=pfx.encode()) as cur:
        k_id = start
        for (k, _) in cur.items():
            expected = f"{pfx}-{k_id:0>10}".encode()
            assert k == expected
            assert k_id < end
            k_id = k_id + 1


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("dur_enable=0")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "pdel").cparams("pfx_len=2")
        kvs = stack.enter_context(kvs_ctx)

        num_keys = 50 * 1000

        kvs.prefix_delete(b"AA")

        add_keys(kvs=kvs, pfx="AA", start=0, end=num_keys)
        add_keys(kvs=kvs, pfx="AB", start=0, end=num_keys)
        add_keys(kvs=kvs, pfx="AC", start=0, end=num_keys)
        add_keys(kvs=kvs, pfx="AD", start=0, end=num_keys)

        kvdb.sync()

        kvs.prefix_delete(b"AB")

        add_keys(kvs=kvs, pfx="AA", start=num_keys, end=2 * num_keys)
        add_keys(kvs=kvs, pfx="AB", start=num_keys, end=2 * num_keys)
        add_keys(kvs=kvs, pfx="AC", start=num_keys, end=2 * num_keys)
        add_keys(kvs=kvs, pfx="AD", start=num_keys, end=2 * num_keys)

        kvs.prefix_delete(b"AC")

        verify_keys(kvs=kvs, pfx="AA", start=0, end=2 * num_keys)
        verify_keys(kvs=kvs, pfx="AB", start=num_keys, end=2 * num_keys)
        verify_keys(kvs=kvs, pfx="AC", start=0, end=0)
        verify_keys(kvs=kvs, pfx="AD", start=0, end=2 * num_keys)
finally:
    hse.fini()
