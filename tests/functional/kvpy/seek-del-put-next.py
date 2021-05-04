#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "seek_del_put_next")
        kvs = stack.enter_context(kvs_ctx)

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
