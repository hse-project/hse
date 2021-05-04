#!/usr/bin/env python3
from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "bug_update_add_key")
        kvs = stack.enter_context(kvs_ctx)

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
