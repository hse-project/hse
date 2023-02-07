#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

# Verify scanning an empty kvs works

kvsname = "scan_empty_kvs"

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, kvsname)
        kvs = stack.enter_context(kvs_ctx)

        with kvs.cursor() as cur:
            s = sum(1 for _ in cur.items())
            assert s == 0
finally:
    hse.fini()
