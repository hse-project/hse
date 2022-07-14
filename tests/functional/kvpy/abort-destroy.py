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
        kvs_ctx = lifecycle.KvsContext(kvdb, "abort_destroy").rparams("transactions.enabled=true")
        kvs = stack.enter_context(kvs_ctx)

        txn = kvdb.transaction()
        txn.begin()
        cursor = kvs.cursor(txn=txn)
        txn.abort()
        cursor.destroy()
finally:
    hse.fini()
