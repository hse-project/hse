#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

"""
Test 1: Ptomb in LC
"""


def run_test_1(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"abc01", b"val0", txn=t)  # LC
        kvs.put(b"abc02", b"val0", txn=t)  # LC
        kvs.prefix_delete(b"abc", txn=t)  # LC
        kvdb.sync()
        kvs.put(b"abc01", b"val1", txn=t)  # C0
        kvs.put(b"abc02", b"val1", txn=t)  # C0
        kvs.put(b"abc03", b"val1", txn=t)  # C0
        kvs.put(b"abc04", b"val1", txn=t)  # C0

        with kvs.cursor(filt=b"abc", txn=t) as c:
            kv = c.read()
            assert kv == (b"abc01", b"val1")
            kv = c.read()
            assert kv == (b"abc02", b"val1")

            kv = c.read()
            assert kv == (b"abc03", b"val1")

            c.seek(b"abc02")
            kv = c.read()
            assert kv == (b"abc02", b"val1")


"""
Test 2: Value in LC is older than value in cn. The value in LC in this case is just waiting to be
garbage collected and should not be returned by a get
"""


def run_test_2(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ghi01", b"val1", txn=t)  # LC
        kvdb.sync()

    with kvdb.transaction() as t:
        kvs.put(b"ghi01", b"val2", txn=t)  # C0

    with kvs.cursor(filt=b"ghi") as c:
        kvdb.sync()  # Moves val2 to cn while val1 stays in LC until it's garbage collected

        for (k, v) in c.items():
            getval = kvs.get(k)[0]
            assert v
            assert v.decode() == "val2"
            assert v == getval
    pass


"""
Test 3: Ptomb in LC. Get and Prefix probe
"""


def run_test_3(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"jkl01", b"val1", txn=t)
        kvs.put(b"jkl02", b"val1", txn=t)
        kvs.put(b"jkl03", b"val1", txn=t)

    with kvdb.transaction() as t:
        kvs.prefix_delete(b"jkl", txn=t)
        kvs.put(b"jkl03", b"val2", txn=t)
        kvdb.sync()

        assert kvs.get(b"jkl01", txn=t)[0] is None
        assert kvs.get(b"jkl03", txn=t)[0] == b"val2"

        cnt, k, _, v, _ = kvs.prefix_probe(b"jkl", txn=t)
        assert cnt == hse.KvsPfxProbeCnt.ONE
        assert (k, v) == (b"jkl03", b"val2")
    pass


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = (
            lifecycle.KvsContext(kvdb, "lc_cursor_test1")
            .cparams("prefix.length=3", "suffix.length=2")
            .rparams("transactions.enabled=true")
        )
        kvs = stack.enter_context(kvs_ctx)

        run_test_1(kvdb, kvs)
        kvdb.sync()

        run_test_2(kvdb, kvs)
        kvdb.sync()

        run_test_3(kvdb, kvs)
        kvdb.sync()
finally:
    hse.fini()
