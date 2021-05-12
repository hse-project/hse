#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "basic", p) as kvs:
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
    hse.fini()
