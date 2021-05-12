#!/usr/bin/env python3
import hse

import util

hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bug_wrong_view_value", p) as kvs:
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
    hse.fini()
