#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs1_ctx = lifecycle.KvsContext(kvdb, "no-compression")
        kvs1 = stack.enter_context(kvs1_ctx)
        kvs2_ctx = lifecycle.KvsContext(kvdb, "compression").rparams()
        kvs2 = stack.enter_context(kvs2_ctx)

        original_sz = kvdb.storage_info.used_bytes

        for i in range(100000):
            kvs1.put(str(i).encode(), 500 * b"A")

        kvdb.compact()
        kvdb.sync()

        kvs1_sz = kvdb.storage_info.used_bytes - original_sz

        for i in range(100000):
            kvs2.put(str(i).encode(), 500 * b"A", flags=hse.KvsPutFlags.VCOMP_OFF)

        kvdb.compact()
        kvdb.sync()

        kvs2_sz = kvdb.storage_info.used_bytes - kvs1_sz - original_sz

        assert kvs2_sz > kvs1_sz
finally:
    hse.fini()
