#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from utility import lifecycle

from hse3 import hse

kvs1_name = "kvs1"
kvs2_name = "kvs2"

hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs1_ctx = lifecycle.KvsContext(kvdb, kvs1_name)
        kvs1 = stack.enter_context(kvs1_ctx)
        kvs2_ctx = lifecycle.KvsContext(kvdb, kvs2_name).rparams(
            "compression.value.algorithm=lz4"
        )
        kvs2 = stack.enter_context(kvs2_ctx)

        original_sz = kvdb.storage_info.used_bytes

        for i in range(100000):
            kvs1.put(str(i).encode(), 500 * b"A")

        kvdb.compact()
        kvdb.sync()

        kvs1_sz = kvdb.storage_info.used_bytes - original_sz

        for i in range(100000):
            kvs2.put(str(i).encode(), 500 * b"A")

        kvdb.compact()
        kvdb.sync()

        kvs2_sz = kvdb.storage_info.used_bytes - kvs1_sz - original_sz

        assert kvs2_sz < kvs1_sz
finally:
    hse.fini()
