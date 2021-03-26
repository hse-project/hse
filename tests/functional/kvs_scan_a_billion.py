#!/usr/bin/env python3
import hse
import sys

# Scan a billion keys

keycount = 1000*1000*1000
kvsname = 'scan_a_billion'

hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make(kvsname)
    kvs = kvdb.kvs_open(kvsname)

    for i in range(keycount):
        key = f'key{i}'.encode()
        kvs.put(key, None)

    with kvs.cursor() as cur:
        s = sum(1 for _ in cur.items())
        assert s == keycount
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop(kvsname)
        kvdb.close()

hse.fini()
