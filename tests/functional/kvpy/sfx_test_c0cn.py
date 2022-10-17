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
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_c0cn").cparams("prefix.length=1")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbaXX", b"42")
        kvs.put(b"AbcXX", b"42")
        kvs.put(b"AbdXX", b"42")
        kvdb.sync()

        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"42")

        kvs.put(b"AbcXY", b"42")  # second (multiple) in c0
        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL

        kvs.prefix_delete(b"A")
        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ZERO
        kvdb.sync()
        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ZERO

        kvs.put(b"AbcXX", b"44")
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"44")
        kvdb.sync()
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"44")

        # duplicate in c0 and cn
        kvs.put(b"AbcXX", b"45")
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"45")
        kvdb.sync()
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbcXX", b"45")
finally:
    hse.fini()
