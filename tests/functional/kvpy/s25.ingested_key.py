#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "ingested_key", p) as kvs:
            kvs.put(b"a", b"1")

            cursor = kvs.cursor()
            kvdb.sync()

            kv = cursor.read()
            assert kv == (b"a", b"1")

            cursor.read()
            assert cursor.eof

            cursor.destroy()
finally:
    hse.fini()
