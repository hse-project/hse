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
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_c0").cparams("prefix.length=1")

        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbaXX", b"42")
        kvs.put(b"AbcXX", b"42")
        kvs.put(b"AbdXX", b"42")

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"42")

        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)
        kvs.put(b"AbcXX", b"43")  # duplicate

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"43")

        kvs.put(b"AbcXY", b"42")  # multiple
        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        kvs.put(b"AbcXZ", b"42")  # multiple
        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL

        kvs.prefix_delete(b"A")
        kvs.put(b"AbcXZ", b"44")
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXZ", b"44")
finally:
    hse.fini()
