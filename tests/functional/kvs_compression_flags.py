#!/usr/bin/env python3

from contextlib import ExitStack
from hse2 import hse
from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs1_ctx = lifecycle.KvsContext(kvdb, "no-compression")
        kvs1 = stack.enter_context(kvs1_ctx)
        kvs2_ctx = lifecycle.KvsContext(kvdb, "compression").rparams(
            "value_compression=lz4"
        )
        kvs2 = stack.enter_context(kvs2_ctx)

        original_sz = kvdb.storage_info.used_bytes

        for i in range(100000):
            kvs1.put(
                str(i).encode(), 500 * b"A"
            )

        kvdb.compact()
        kvdb.sync()

        kvs1_sz = kvdb.storage_info.used_bytes - original_sz

        for i in range(100000):
            kvs2.put(
                str(i).encode(), 500 * b"A", flags=hse.PutFlag.VALUE_COMPRESSION_OFF
            )

        kvdb.compact()
        kvdb.sync()

        kvs2_sz = kvdb.storage_info.used_bytes - kvs1_sz - original_sz

        assert kvs2_sz > kvs1_sz
finally:
    hse.fini()
