#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "cn_update", p) as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")
            kvs.put(b"c", b"3")

            cur = kvs.cursor()
            assert sum(1 for _ in cur.items()) == 3

            kvdb.sync()

            kvs.put(b"d", b"4")
            kvs.put(b"e", b"5")
            kvs.put(b"a", b"100")

            cur.update()
            assert sum(1 for _ in cur.items()) == 2  # keys beyond 'c' = 'd' and 'e'
            cur.seek(b"0x0")
            assert sum(1 for _ in cur.items()) == 5

            cur.destroy()
finally:
    hse.fini()
