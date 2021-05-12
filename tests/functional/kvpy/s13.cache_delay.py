#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "cache_delay", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")
            kvs.put(b"c", b"3")

            cursor = kvs.cursor()

            kv = cursor.read()
            assert kv == (b"a", b"1")

            kvs.put(b"d", b"4")

            kv = cursor.read()
            assert kv == (b"b", b"2")
            kv = cursor.read()
            assert kv == (b"c", b"3")
            cursor.read()
            assert cursor.eof

            cursor.destroy()

            cursor = kvs.cursor()

            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"2")
            kv = cursor.read()
            assert kv == (b"c", b"3")
            kv = cursor.read()
            assert kv == (b"d", b"4")
            cursor.read()
            assert cursor.eof

            cursor.destroy()

            kvs.put(b"e", b"5")

            cursor = kvs.cursor()

            assert sum(1 for _ in cursor.items()) == 5

            cursor.destroy()
finally:
    hse.fini()
