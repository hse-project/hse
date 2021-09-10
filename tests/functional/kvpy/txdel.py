#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack
from hse2 import hse

from utility import lifecycle, cli


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "txdel").rparams("transactions.enabled=true")
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"pfx.a", b"1", txn=txn)
            kvs.put(b"pfx.b", b"2", txn=txn)
            kvs.put(b"pfx.c", b"3", txn=txn)

        with kvdb.transaction() as txn:
            with kvs.cursor(b"pfx", txn=txn) as cur:
                kv = cur.read()
                assert kv == (b"pfx.a", b"1")
                kv = cur.read()
                assert kv == (b"pfx.b", b"2")
                kv = cur.read()
                assert kv == (b"pfx.c", b"3")
                cur.read()
                assert cur.eof

        with kvdb.transaction() as txn:
            kvs.delete(b"pfx.c", txn=txn)

        with kvdb.transaction() as txn:
            with kvs.cursor(b"pfx", txn=txn) as cur:
                kv = cur.read()
                assert kv == (b"pfx.a", b"1")
                kv = cur.read()
                assert kv == (b"pfx.b", b"2")
                cur.read()
                assert cur.eof
finally:
    hse.fini()
