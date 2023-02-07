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
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_tomb").cparams("prefix.length=1")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbcXX", b"1")
        kvs.put(b"AbdXX", b"1")
        kvs.put(b"AbdXY", b"2")
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        cnt, *_ = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.MUL

        kvs.delete(b"AbdXY")
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbdXX", b"1")
        kvdb.sync()
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbdXX", b"1")

        # Multiple tombs
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"1")

        kvs.prefix_delete(b"A")

        kvs.put(b"AbcX1", b"1")
        kvs.put(b"AbcX2", b"1")
        kvs.put(b"AbcX3", b"1")
        kvs.put(b"AbcX4", b"1")
        kvs.put(b"AbcX5", b"1")
        kvs.put(b"AbcX6", b"1")
        kvdb.sync()
        kvs.put(b"AbcX7", b"1")
        kvs.put(b"AbcX8", b"1")
        kvs.put(b"AbcX9", b"1")

        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL

        kvs.delete(b"AbcX1")
        kvs.delete(b"AbcX2")
        kvs.delete(b"AbcX3")
        kvs.delete(b"AbcX7")
        kvs.delete(b"AbcX8")

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcX9", b"1")

        kvs.delete(b"AbcX9")

        # The only remaining keys are in cn. A prefix probe in a cn kvset will see keys in order.
        # So a probe can expect the smallest key in the cn kvset.
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcX4", b"1")

        kvdb.sync()
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        assert (k, v) == (b"AbcX4", b"1")
finally:
    hse.fini()
