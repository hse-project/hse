#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack
from typing import List

from utility import cli, lifecycle

from hse3 import hse


def check_keys(cursor: hse.KvsCursor, expected: List[bytes]):
    actual = [k for k, _ in cursor.items()]
    assert len(actual) == len(expected)
    for x, y in zip(expected, actual):
        assert x == y


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "update_views").rparams("transactions.enabled=true")
        kvs = stack.enter_context(kvs_ctx)

        with kvdb.transaction() as t:
            kvs.put(b"a", b"1", txn=t)
            kvs.put(b"b", b"2", txn=t)
            kvs.put(b"d", b"4", txn=t)

        txn = kvdb.transaction()
        txn.begin()
        cursor = kvs.cursor(txn=txn)

        with kvdb.transaction() as t:
            kvs.put(b"f", b"6", txn=t)

        check_keys(cursor, [b"a", b"b", b"d"])

        txn.abort()
        txn.begin()

        cursor.read()
        assert cursor.eof

        txn1 = kvdb.transaction()
        txn1.begin()
        with kvdb.transaction() as t:
            kvs.put(b"c", b"3", txn=t)
        kvs.put(b"x", b"1", txn=txn1)

        txn2 = kvdb.transaction()
        txn2.begin()
        with kvdb.transaction() as t:
            kvs.put(b"e", b"5", txn=t)
        kvs.put(b"y", b"2", txn=txn2)

        cursor.read()
        assert cursor.eof

        cursor.destroy()
finally:
    hse.fini()
