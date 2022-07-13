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
        kvs_ctx = lifecycle.KvsContext(kvdb, "cn_update")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")
        kvs.put(b"c", b"3")

        cur = kvs.cursor()
        assert sum(1 for _ in cur.items()) == 3

        kvdb.sync()

        kvs.put(b"d", b"4")
        kvs.put(b"e", b"5")
        kvs.put(b"a", b"100")

        cur.update_view()
        assert sum(1 for _ in cur.items()) == 2  # keys beyond 'c' = 'd' and 'e'
        cur.seek(b"0x0")
        assert sum(1 for _ in cur.items()) == 5

        cur.destroy()
finally:
    hse.fini()
