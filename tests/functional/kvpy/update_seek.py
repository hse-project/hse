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
        kvs_ctx = lifecycle.KvsContext(kvdb, "update_seek")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"a", b"1")
        kvs.put(b"b", b"2")
        kvs.put(b"c", b"3")
        kvs.put(b"d", b"4")

        cursor = kvs.cursor()
        cursor.seek(b"c")
        check_keys(cursor, [b"c", b"d"])

        cursor.seek(b"c")
        cursor.update_view()
        check_keys(cursor, [b"c", b"d"])
        cursor.destroy()

        kvdb.sync()
        cursor = kvs.cursor()
        cursor.seek(b"c")
        check_keys(cursor, [b"c", b"d"])

        cursor.seek(b"c")
        cursor.update_view()
        check_keys(cursor, [b"c", b"d"])
        cursor.destroy()
finally:
    hse.fini()
