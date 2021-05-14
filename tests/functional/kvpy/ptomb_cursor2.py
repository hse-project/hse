#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest
    p.set(key="kvs.pfx_len", value="3")

    # Test 1: Update after seek. Seek can be to an existing key or non-existent key
    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "ptomb_cursor2", p) as kvs:
            kvs.prefix_delete(b"key")
            kvs.put(b"key1", b"val1")
            kvs.put(b"key2", b"val1")
            kvs.put(b"key3", b"val1")
            kvs.put(b"key4", b"val1")

            with kvs.cursor() as c:
                kv = c.read()
                assert kv == (b"key1", b"val1")
                kv = c.read()
                assert kv == (b"key2", b"val1")

                c.update()
                kv = c.read()
                assert kv == (b"key3", b"val1")

                c.seek(b"key2")
                c.update()
                kv = c.read()
                assert kv == (b"key2", b"val1")

            kvs.prefix_delete(b"key")
            kvs.put(b"key1", b"val2")
            kvs.put(b"key2", b"val2")
            kvs.put(b"key3", b"val2")
            kvs.put(b"key4", b"val2")

            with kvs.cursor() as c:
                kv = c.read()
                assert kv == (b"key1", b"val2")
                kv = c.read()
                assert kv == (b"key2", b"val2")

                kvs.prefix_delete(b"key")
                kvs.put(b"key3", b"val3")
                kvs.put(b"key4", b"val3")

                c.update()
                kv = c.read()
                assert kv == (b"key3", b"val3")

                c.seek(b"key2")
                c.update()
                kv = c.read()
                assert kv == (b"key3", b"val3")

            c.destroy()
finally:
    hse.fini()
