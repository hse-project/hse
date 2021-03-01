#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs9")
    kvs = kvdb.kvs_open("kvs9")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")
    kvs.put(b"c", b"3")

    kvdb.sync()

    kvs.delete(b"c")

    with kvs.cursor() as cur:
        kv = cur.read()
        assert kv == (b"a", b"1")
        kv = cur.read()
        assert kv == (b"b", b"2")
        cur.read()
        assert cur.eof
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs9")
        kvdb.close()

hse.Kvdb.fini()
