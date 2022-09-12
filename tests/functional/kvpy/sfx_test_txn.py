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
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = (
            lifecycle.KvsContext(kvdb, "sfx_test_txn")
            .cparams("prefix.length=1")
            .rparams("transactions.enabled=true")
        )

        kvs = stack.enter_context(kvs_ctx)

        # Add a few keys
        with kvdb.transaction() as T0:
            kvs.put(b"AbcXX", b"1", txn=T0)
            kvs.put(b"AbdXX", b"1", txn=T0)
            kvs.put(b"AbdXX", b"2", txn=T0)

        # Start transaction T1
        T1 = kvdb.transaction()
        T1.begin()

        # Flush c0. Push the 3 keys into cn.
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        # Insert a new key into c0 using a separate txn T2
        with kvdb.transaction() as T2:
            kvs.put(b"AbcXY", b"2", txn=T2)

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc", txn=T1)
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"1")

        # Flush c0. Push {AbcXY,2} into cn.
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        kvs.put(b"AbcXZ", b"3", txn=T1)

        # The probe call should see the newly added kv pair in c0 {AbcXZ,3}
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc", txn=T1)
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcXZ", b"3")

        # Probe prefix "Abc" from a separate txn T3
        with kvdb.transaction() as T3:
            cnt, k, _, v, _ = kvs.prefix_probe(b"Abc", txn=T3)  # outside txn
            assert cnt == hse.KvsPfxProbeCnt.MUL
            assert (k, v) == (b"AbcXY", b"2")

        T1.commit()

        # After committing T1, a probe should see the first key in the newest KVMS {AbcXZ,3}
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcXZ", b"3")
finally:
    hse.fini()
