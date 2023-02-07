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
        kvs_ctx = lifecycle.KvsContext(kvdb, "sfx_test_cn").cparams("prefix.length=1")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"AbcXX", b"42")
        kvs.put(b"AbdXX", b"42")
        kvdb.sync()

        kvs.put(b"AbcXX", b"44")
        kvs.put(b"AbcXY", b"43")
        kvs.put(b"AbeGarbageXY", b"43")
        kvs.put(b"BcdXX", b"42")
        kvdb.sync()

        kvs.put(b"AbaXX", b"42")
        kvs.put(b"AbeGarbageXY", b"44")
        kvdb.sync()

        cnt, *_ = kvs.prefix_probe(b"Abc")
        assert cnt == hse.KvsPfxProbeCnt.MUL
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbdXX", b"42")

        kvs.put(b"AbdXX", b"43")
        cnt, k, _, v, _ = kvs.prefix_probe(b"Abd")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbdXX", b"43")

        kvs.prefix_delete(b"A")
        kvs.put(b"AbeGarbageXY", b"45")
        kvdb.sync()

        cnt, k, _, v, _ = kvs.prefix_probe(b"AbeGarbage")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbeGarbageXY", b"45")

        kvs.prefix_delete(b"A")
        kvs.put(b"AbeGarbageXZ", b"46")
        kvdb.sync()

        cnt, k, _, v, _ = kvs.prefix_probe(b"AbeGarbage")
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"AbeGarbageXZ", b"46")
finally:
    hse.fini()
