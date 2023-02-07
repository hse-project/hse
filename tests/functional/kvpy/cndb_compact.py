#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

'''
Set the cndb compaction high watermark to a very low percentage - 0.02%.

Then load the kvs such that it undergoes multiple kvcompactions and use a cursor
to pin down certain kvsets. This forces cndb compactions to deal with incomplete
and rollforward-able transactions.
'''

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse

import time

def run_test(kvdb: hse.Kvdb, kvs: hse.Kvs, validx: int, keycnt: int = 150):
    val = f"val.{validx:0>4}"
    cur = None

    for i in range(keycnt):
        key = f"key.{i:0>10}"
        kvs.put(key, val)
        kvdb.sync()

        if i == 1:
            cur = kvs.cursor()
            k, v = cur.read()

        if i == 90:
            cur.destroy()

        time.sleep(0.01);

    pass

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false", "c0_debug=16", "cndb_compact_hwm_pct=0.02")
        kvdb = stack.enter_context(kvdb_ctx)

        nkeys = 150
        kvs_name = "test_kvs"

        kvdb.kvs_create(kvs_name)
        kvs = kvdb.kvs_open(kvs_name)

        run_test(kvdb, kvs, 1, keycnt = nkeys)
        run_test(kvdb, kvs, 2, keycnt = nkeys)
        run_test(kvdb, kvs, 3, keycnt = nkeys)

        kvs.close()

        # Reopen kvs and verify the number of keys.
        kvs = kvdb.kvs_open(kvs_name)
        with kvs.cursor() as cur:
            assert sum(1 for _ in cur.items()) == nkeys

        kvs.close()
finally:
    hse.fini()
