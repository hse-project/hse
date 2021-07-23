#!/usr/bin/env python3

from contextlib import ExitStack
from hse2 import hse

from utility import lifecycle, cli

# Verify scanning a KVS full of tombstones returns nothing

keycount = 1000 * 1000
kvsname = "scan_deleted_keys"

hse.init(cli.HOME)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, kvsname)
        kvs = stack.enter_context(kvs_ctx)

        for i in range(keycount):
            key = f"key{i}".encode()
            kvs.put(key, None)
            kvs.delete(key)

        with kvs.cursor() as cur:
            s = sum(1 for _ in cur.items())
            assert s == 0
finally:
    hse.fini()
