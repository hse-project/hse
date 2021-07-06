#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle

hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "bug_wrong_view_value")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")

        with kvs.cursor() as cur:
            # replace a, outside of view of cursor
            kvs.put(b"a", b"3")

            kv = cur.read()
            assert kv == (b"a", b"1")
            cur.read()
            cur.read()

            cur.update_view()
            cur.seek(b"a")

            kv = cur.read()
            assert kv == (b"a", b"3")
finally:
    hse.fini()
