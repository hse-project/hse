#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

"""
Create multiple c0 KVMSes and use a cursor to verify the keys. Update this cursor (explicitly as
well as through the cursor cache: destroy + create) and verify the keys again.
"""

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse


def resize_c0_cursor(kvdb: hse.Kvdb, kvs: hse.Kvs):
    cnt1 = 10
    cnt2 = 30

    for i in range(cnt1):
        key = "ab{:0>6}".format(i)
        kvs.put(key, "val")
        kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

    with kvs.cursor(filt="ab") as c:
        assert sum(1 for _ in c.items()) == cnt1
        kvdb.sync()  # Push all keys to cn and start fresh

        for i in range(cnt1, cnt1 + cnt2):
            key = "ab{:0>6}".format(i)
            kvs.put(key, "val")
            kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

        c.update_view()
        c.seek("ab")
        assert sum(1 for _ in c.items()) == cnt1 + cnt2


def reuse_c0_cursor(kvdb: hse.Kvdb, kvs: hse.Kvs):
    kvs.put("ab01", "val01")
    kvs.put("ab02", "val01")
    kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

    with kvs.cursor(filt="ab") as c:
        assert sum(1 for _ in c.items()) == 2

    kvs.put("ab03", "val01")
    kvs.put("ab04", "val01")
    kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

    kvs.put("ab05", "val01")
    kvs.put("ab06", "val01")
    kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

    kvs.put("ab07", "val01")
    kvs.put("ab08", "val01")
    kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

    with kvs.cursor(filt="ab") as c:
        assert sum(1 for _ in c.items()) == 8

    kvs.put("ab09", "val01")
    kvs.put("ab10", "val01")
    kvdb.sync(flags=hse.KvdbSyncFlag.ASYNC)

    with kvs.cursor(filt="ab") as c:
        assert sum(1 for _ in c.items()) == 10


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams(
            "durability.enabled=false", "c0_debug=16"
        )
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "test_kvs").cparams("prefix.length=2")

        with kvs_ctx as kvs:
            reuse_c0_cursor(kvdb, kvs)

        with kvs_ctx as kvs:
            resize_c0_cursor(kvdb, kvs)
finally:
    hse.fini()
