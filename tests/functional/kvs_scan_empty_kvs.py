#!/usr/bin/env python3
import hse
import sys

# Verify scanning an empty kvs works

kvsname = 'scan_empty_kvs'

hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make(kvsname)
    kvs = kvdb.kvs_open(kvsname)

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
