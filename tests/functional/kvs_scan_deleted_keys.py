#!/usr/bin/env python3
import hse
import sys

# Verify scanning a KVS full of tombstones returns nothing

keycount = 1000*1000
kvsname = 'scan_deleted_keys'

hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make(kvsname)
    kvs = kvdb.kvs_open(kvsname)

    for i in range(keycount):
        key = f'key{i}'.encode()
        kvs.put(key, None)
        kvs.delete(key)

    with kvs.cursor() as cur:
        s = sum(1 for _ in cur.items())
        assert s == 0
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop(kvsname)
        kvdb.close()

hse.fini()
