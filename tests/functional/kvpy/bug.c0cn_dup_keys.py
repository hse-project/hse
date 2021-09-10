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
        kvs_ctx = lifecycle.KvsContext(kvdb, "c0cn_dup_keys")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"0x0001", b"0x0001")
        kvs.put(b"0x0010", b"0x0010")
        kvs.put(b"0x0002", b"0x0002")
        kvs.put(b"0xff00", b"0xff00")
        kvs.put(b"0x000f", b"0x000f")
        kvs.put(b"0x0006", b"0x0006")
        kvs.put(b"0x0003", b"0x0003")
        kvs.put(b"0x0004", b"0x0004")

        cur = kvs.cursor()
        count = sum(1 for _ in cur.items())
        assert count == 8
        cur.destroy()

        cur = kvs.cursor(b"0x00")
        count = sum(1 for _ in cur.items())
        assert count == 7
        cur.destroy()

        cur = kvs.cursor(b"0xff")
        count = sum(1 for _ in cur.items())
        assert count == 1
        cur.destroy()
finally:
    hse.fini()
