#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack
from hse2 import hse

from utility import lifecycle, cli


hse.init(cli.HOME)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "ptomb_cursor2").cparams("prefix.length=3")
        kvs = stack.enter_context(kvs_ctx)

        # Test 1: Update after seek. Seek can be to an existing key or non-existent key
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

            c.update_view()
            kv = c.read()
            assert kv == (b"key3", b"val1")

            c.seek(b"key2")
            c.update_view()
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

            c.update_view()
            kv = c.read()
            assert kv == (b"key3", b"val3")

            c.seek(b"key2")
            c.update_view()
            kv = c.read()
            assert kv == (b"key3", b"val3")

        c.destroy()
finally:
    hse.fini()
