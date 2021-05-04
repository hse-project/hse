#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("dur_enable=0")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "ingested_key")
        kvs = stack.enter_context(kvs_ctx)

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
