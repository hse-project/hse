#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs14")
    kvs = kvdb.kvs_open("kvs14")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")
    kvs.delete(b"a")

    with kvs.cursor() as cur:
        cur.seek(b"a")
        kv = cur.read()
        assert kv == (b"b", b"2")
        cur.read()
        assert cur.eof

        kvdb.sync()

        cur.update()
        cur.seek(b"a")
        kv = cur.read()
        assert kv == (b"b", b"2")
        cur.read()

        kvs.delete(b"b")
        cur.update()
        cur.seek(b"b")
        kv = cur.read()
        assert kv == (None, None) and cur.eof
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs14")
        kvdb.close()

hse.Kvdb.fini()
