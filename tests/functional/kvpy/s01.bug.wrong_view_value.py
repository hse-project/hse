#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs1")
    kvs = kvdb.kvs_open("kvs1")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")

    with kvs.cursor() as cur:
        # replace a, outside of view of cursor
        kvs.put(b"a", b"3")

        kv = cur.read()
        assert kv == (b"a", b"1")
        cur.read()
        cur.read()

        cur.update()
        cur.seek(b"a")

        kv = cur.read()
        assert kv == (b"a", b"3")
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs1")
        kvdb.close()


hse.Kvdb.fini()
