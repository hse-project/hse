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
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = (
            lifecycle.KvsContext(kvdb, "sfx_test_txn")
            .cparams("prefix.length=1", "suffix.length=2")
            .rparams("transactions.enabled=true")
        )

        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as txn:
            kvs.put(b"AbcXX", b"1", txn=txn)
            kvs.put(b"AbdXX", b"1", txn=txn)
            kvs.put(b"AbdXX", b"2", txn=txn)

        txn = kvdb.transaction()
        txn.begin()

        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)
        with kvdb.transaction() as t:
            kvs.put(b"AbcXY", b"2", txn=t)

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc", txn=txn)
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"1")

        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)
        kvs.put(b"AbcXZ", b"3", txn=txn)
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc", txn=txn)  # inside txn
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcXZ", b"3")
        with kvdb.transaction() as t:
            cnt, k, _, v, _ = kvs.prefix_probe(b"Abc", txn=t)  # outside txn
            assert cnt == hse.KvsPfxProbeCnt.MUL
            assert (k, v) == (b"AbcXY", b"2")

        txn.commit()

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcXZ", b"3")
finally:
    hse.fini()
