#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "seek_tomb", p) as kvs:
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
    hse.fini()
