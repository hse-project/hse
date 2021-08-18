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
