#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from hse2 import hse

from utility import lifecycle, cli

import errno

def pdel_before_put(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"old", txn=t)

    t1 = kvdb.transaction()
    t1.begin()
    kvs.prefix_delete(b"ab", txn=t1)

    t2 = kvdb.transaction()
    t2.begin()
    try:
        kvs.put(b"ab01", b"val", txn=t2)
        assert False
    except hse.HseException as e:
        assert e.returncode == errno.ECANCELED

    t2.commit()

    assert kvs.get(b"ab01").decode() == "old"

    t1.commit()
    assert kvs.get(b"ab01") == None

    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"new", txn=t)
    assert kvs.get(b"ab01").decode() == "new"

def put_before_pdel(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"old", txn=t)

    t1 = kvdb.transaction()
    t1.begin()
    kvs.put(b"ab01", b"val", txn=t1)

    t2 = kvdb.transaction()
    t2.begin()
    try:
        kvs.prefix_delete(b"ab", txn=t2)
        assert False
    except hse.HseException as e:
        assert e.returncode == errno.ECANCELED

    t1.commit()
    t2.commit()
    assert kvs.get(b"ab01") == b"val"

def pdel_commits(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"old", txn=t)

    t1 = kvdb.transaction()
    t1.begin()
    kvs.prefix_delete(b"ab", txn=t1)

    t2 = kvdb.transaction()
    t2.begin()

    # Commit pdel. t2 began before this point, so it should not allow puts.
    t1.commit()

    try:
        kvs.put(b"ab01", b"val", txn=t2)
        assert False
    except hse.HseException as e:
        assert e.returncode == errno.ECANCELED

    t2.commit()

    assert kvs.get(b"ab01") == None

def long_put(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"old", txn=t)

    t1 = kvdb.transaction()
    t1.begin()
    kvs.put(b"ab01", b"val", txn=t1)

    t2 = kvdb.transaction()
    t2.begin()

    try:
        kvs.prefix_delete(b"ab", txn=t2)
        assert False
    except hse.HseException as e:
        assert e.returncode == errno.ECANCELED

    t2.abort()
    t1.commit()

    assert kvs.get(b"ab01") == b"val"

def long_put_abort(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"old", txn=t)

    t1 = kvdb.transaction()
    t1.begin()

    kvs.put(b"ab01", b"val", txn=t1)

    t2 = kvdb.transaction()
    t2.begin()

    t1.commit()

    t3 = kvdb.transaction()
    t3.begin()

    kvs.prefix_delete(b"ab", txn=t3)
    t3.abort()

    try:
        kvs.put(b"ab01", b"val2", txn=t2)
        assert False
    except hse.HseException as e:
        assert e.returncode == errno.ECANCELED
    t2.abort()

    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"new", txn=t)
    assert kvs.get(b"ab01").decode() == "new"

def short_put(kvdb: hse.Kvdb, kvs: hse.Kvs):
    with kvdb.transaction() as t:
        kvs.put(b"ab01", b"old", txn=t)

    t1 = kvdb.transaction()
    t1.begin()
    t2 = kvdb.transaction()
    t2.begin()

    kvs.put(b"ab01", b"val", txn=t1)
    t1.commit()

    try:
        kvs.prefix_delete(b"ab", txn=t2)
        assert False
    except hse.HseException as e:
        assert e.returncode == errno.ECANCELED

    t2.abort()

hse.init(cli.HOME)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("dur_enable=0")
        kvdb = stack.enter_context(kvdb_ctx)

        kvs_ctx = lifecycle.KvsContext(kvdb, "test_kvs").cparams("pfx_len=2").rparams("transactions_enable=1")

        with kvs_ctx as kvs:
            pdel_before_put(kvdb, kvs)

        with kvs_ctx as kvs:
            put_before_pdel(kvdb, kvs)

        with kvs_ctx as kvs:
            pdel_commits(kvdb, kvs)

        with kvs_ctx as kvs:
            long_put(kvdb, kvs)

        with kvs_ctx as kvs:
            long_put_abort(kvdb, kvs)

        with kvs_ctx as kvs:
            short_put(kvdb, kvs)

finally:
    hse.fini()
