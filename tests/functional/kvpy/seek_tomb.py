#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "seek_tomb")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")
        kvs.delete(b"a")

        with kvs.cursor() as cur:
            cur.seek(b"a")
            kv = cur.read()
            assert kv == (b"b", b"2")
            cur.read()
            assert cur.eof

            kvdb.sync()

            cur.update_view()
            cur.seek(b"a")
            kv = cur.read()
            assert kv == (b"b", b"2")
            cur.read()

            kvs.delete(b"b")
            cur.update_view()
            cur.seek(b"b")
            kv = cur.read()
            assert kv == (None, None) and cur.eof
finally:
    hse.fini()
