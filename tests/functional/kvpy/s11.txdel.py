#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs11")
    kvs = kvdb.kvs_open("kvs11")

    kvs.put(b"pfx.a", b"1")
    kvs.put(b"pfx.b", b"2")
    kvs.put(b"pfx.c", b"3")

    with kvs.cursor(b"pfx") as cur:
        kv = cur.read()
        assert kv == (b"pfx.a", b"1")
        kv = cur.read()
        assert kv == (b"pfx.b", b"2")
        kv = cur.read()
        assert kv == (b"pfx.c", b"3")
        cur.read()
        assert cur.eof

    with kvdb.transaction() as txn:
        kvs.delete(b"pfx.c", txn=txn)

    with kvs.cursor(b"pfx") as cur:
        kv = cur.read()
        assert kv == (b"pfx.a", b"1")
        kv = cur.read()
        assert kv == (b"pfx.b", b"2")
        cur.read()
        assert cur.eof
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.close()

hse.Kvdb.fini()
