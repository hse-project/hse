#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bug_update_new_kvms", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")

            cursor = kvs.cursor()
            kv = cursor.read()
            assert kv == (b"a", b"1")
            kv = cursor.read()
            assert kv == (b"b", b"2")
            cursor.read()
            assert cursor.eof

            kvdb.flush()

            kvs.put(b"c", b"3")
            kvdb.flush()

            kvs.put(b"d", b"4")
            kvdb.flush()

            kvs.put(b"e", b"5")
            kvdb.flush()

            kvs.put(b"f", b"6")

            with kvdb.transaction() as txn:
                kvs.put(b"c", b"3")

            cursor.update()
            cursor.seek(b"0x00")

            assert sum(1 for _ in cursor.items()) == 6

            cursor.destroy()
finally:
    hse.fini()
