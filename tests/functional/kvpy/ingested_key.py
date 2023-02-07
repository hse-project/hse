#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
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
