#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

'''
This test inserts keys in 2 KVSes and makes sure that a cursor over one kvs returns keys only
from that kvs. This test is focussed mainly on LC.

To add keys to LC and make sure that an unintended ingest doesn't move it all to cn set these
two run time params:
    1. durability.enabled = false // kvdb_sync() ingests to lc + cn
    2. c0_debug = 16              // ingest only when sync is called. See C0_DEBUG_ACCUMULATE in hse.
'''

from contextlib import ExitStack

from hse2 import hse

from utility import lifecycle, cli

'''
Key in c0 matches a key in lc from another kvs
'''
def test_case_01(kvdb, kvs1, kvs2):
    with kvdb.transaction() as t:
        kvs1.put(b"ab02", b"val-lc", txn=t)
        kvs2.put(b"ab03", b"val-lc-wrong-kvs", txn=t)
        kvdb.sync()

    with kvdb.transaction() as t:
        kvs1.put(b"ab03", b"val-c0", txn=t)

    with kvs1.cursor(filt=b"ab") as c:
        assert c.read() == (b'ab02', b'val-lc')
        assert c.read() == (b'ab03', b'val-c0')
        assert c.read() == (None, None)

    with kvs1.cursor(filt=b"ab", flags=hse.CursorCreateFlag.REV) as c:
        assert c.read() == (b'ab03', b'val-c0')
        assert c.read() == (b'ab02', b'val-lc')
        assert c.read() == (None, None)

'''
Empty c0. LC contains keys from both KVSes. All keys share a common pfx.
'''
def test_case_02(kvdb, kvs1, kvs2):
    with kvdb.transaction() as t:
        kvs1.put(b"ab01", b"val-cn", txn=t)

    with kvdb.transaction() as t:
        kvs2.put(b"ab03", b"val-lc", txn=t)
        kvs1.put(b"ab04", b"val-lc", txn=t)
        kvdb.sync()

    with kvs1.cursor(filt=b"ab") as c:
        assert c.read() == (b'ab01', b'val-cn')
        assert c.read() == (b'ab04', b'val-lc')
        assert c.read() == (None, None)

    with kvs1.cursor(filt=b"ab", flags=hse.CursorCreateFlag.REV) as c:
        assert c.read() == (b'ab04', b'val-lc')
        assert c.read() == (b'ab01', b'val-cn')
        assert c.read() == (None, None)

'''
LC contains data from other kvs. All keys share a common pfx.
'''
def test_case_03(kvdb, kvs1, kvs2):
    with kvdb.transaction() as t:
        kvs1.put(b"ab01", b"val-cn", txn=t)

    with kvdb.transaction() as t:
        kvs2.put(b"ab02", b"val-lc-wrong", txn=t)
        kvs2.put(b"ab03", b"val-lc-wrong", txn=t)
        kvs2.put(b"ab04", b"val-lc-wrong", txn=t)
        kvdb.sync()

    with kvdb.transaction() as t:
        kvs1.put(b"ab02", b"val-c0", txn=t)

    with kvs1.cursor(filt=b"ab") as c:
        assert c.read() == (b'ab01', b'val-cn')
        assert c.read() == (b'ab02', b'val-c0')
        assert c.read() == (None, None)

    with kvs1.cursor(filt=b"ab", flags=hse.CursorCreateFlag.REV) as c:
        assert c.read() == (b'ab02', b'val-c0')
        assert c.read() == (b'ab01', b'val-cn')
        assert c.read() == (None, None)

def run_test(kvdb, kvs1, kvs2, func):
    with kvs1 as k1:
        with kvs2 as k2:
            func(kvdb, k1, k2)
    pass

hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false", "c0_debug=16")
        kvdb = stack.enter_context(kvdb_ctx)

        kvs1 = lifecycle.KvsContext(kvdb, "kvs1").cparams("prefix.length=2", "suffix.length=1").rparams("transactions.enabled=true")
        kvs2 = lifecycle.KvsContext(kvdb, "kvs2").cparams("prefix.length=2", "suffix.length=1").rparams("transactions.enabled=true")

        run_test(kvdb, kvs1, kvs2, test_case_01)
        run_test(kvdb, kvs1, kvs2, test_case_02)
        run_test(kvdb, kvs1, kvs2, test_case_03)

finally:
    hse.fini()
