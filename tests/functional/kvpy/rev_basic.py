#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "rev_basic", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")
            assert kvs.get(b"a") == b"1"
            assert kvs.get(b"b") == b"2"

            cursor = kvs.cursor(reverse=True)
            kv = cursor.read()
            assert kv == (b"b", b"2")
            kv = cursor.read()
            assert kv == (b"a", b"1")
            cursor.read()
            assert cursor.eof

            cursor.seek(b"b")
            kv = cursor.read()
            assert kv == (b"b", b"2")

            cursor.seek(b"a")
            kv = cursor.read()
            assert kv == (b"a", b"1")

            cursor.destroy()
finally:
    hse.fini()
