#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "seek_del_put_next", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")
            kvs.put(b"c", b"3")

            cursor = kvs.cursor()
            cursor.seek(b"a")

            kvs.delete(b"a")
            kvs.put(b"a", b"11")

            cursor.update()
            kv = cursor.read()
            assert kv == (b"a", b"11")

            cursor.destroy()
finally:
    hse.fini()
