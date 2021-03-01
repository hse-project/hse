#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs0")
    kvs = kvdb.kvs_open("kvs0")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")
    assert kvs.get(b"a") == b"1"
    assert kvs.get(b"b") == b"2"

    with kvs.cursor() as cur:
        kv = cur.read()
        assert kv == (b"a", b"1")
        kv = cur.read()
        assert kv == (b"b", b"2")
        cur.read()
        assert cur.eof
        cur.seek(b"a")
        kv = cur.read()
        assert kv == (b"a", b"1")
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs0")
        kvdb.close()

hse.Kvdb.fini()
