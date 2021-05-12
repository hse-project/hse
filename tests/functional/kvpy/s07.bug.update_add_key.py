#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bug_update_add_key", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")

            cursor = kvs.cursor()
            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"2")
            cursor.read()
            assert cursor.eof

            kvs.put(b"c", b"3")

            cursor.update()
            cursor.seek(b"0x00")

            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"2")
            kv = cursor.read()
            assert kv == (b"c", b"3")
            cursor.read()
            assert cursor.eof

            cursor.destroy()
finally:
    hse.fini()
