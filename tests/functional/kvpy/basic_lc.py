#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

"""
This test checks basic ingest and get operation in LC.
It creates 2 active transactions, inserts keys in them and calls sync (ingest)
It then checks whether a point get reads the correct uncommitted kv-tuples from LC.
It also checks if the right values are read if a txn is committed or aborted.
"""

from contextlib import ExitStack

from hse2 import hse

from utility import lifecycle, cli


def run_test(kvdb: hse.Kvdb, kvs: hse.Kvs):
    t0 = kvdb.transaction()
    t0.begin()
    t1 = kvdb.transaction()
    t1.begin()

    kvs.put(b"aa1", b"uncommitted-aa1", txn=t0)  # commit
    kvs.put(b"aa2", b"uncommitted-aa2", txn=t0)  # commit
    kvs.put(b"aa3", b"uncommitted-aa3", txn=t1)  # abort

    val = kvs.get(b"aa1", txn=t0)[0]
    assert val == b"uncommitted-aa1"

    with kvdb.transaction() as t5:
        kvs.put(b"ab1", b"val1", txn=t5)
        kvs.put(b"ab2", b"val2", txn=t5)
        kvs.put(b"ab3", b"val3", txn=t5)
    kvdb.sync()

    # Get from C0
    with kvdb.transaction() as t5:
        val = kvs.get(b"ab3", txn=t5)[0]
        assert val == b"val3"

    # Get from LC
    val = kvs.get(b"aa1", txn=t0)[0]
    assert val == b"uncommitted-aa1"  # uncommitted data from current txn
    val = kvs.get(b"aa3", txn=t0)[0]
    assert val == None  # uncommitted data from some other txn
    val = kvs.get(b"aa3", txn=t1)[0]
    assert val == b"uncommitted-aa3"  # uncommitted data from current txn

    t0.commit()
    t1.abort()

    kvdb.sync()

    # Get from CN. Keys were previously in LC.
    with kvdb.transaction() as t5:
        # Committed. Should be visible
        val = kvs.get(b"aa1", txn=t5)[0]
        assert val == b"uncommitted-aa1"

        # Aborted. Should not see this key.
        val = kvs.get(b"aa3", txn=t5)[0]
        assert val == None
    pass


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "basic_lc").rparams("transactions.enabled=true")
        kvs = stack.enter_context(kvs_ctx)
        run_test(kvdb, kvs)
finally:
    hse.fini()
