#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

from contextlib import ExitStack

from utility import cli, lifecycle

from hse3 import hse


def verify(kvs: hse.Kvs, pfx: str, cnt: int):
    # [HSE_REVISIT] Getting all keys is too slow/freezes
    get_cnt = 100
    if cnt < get_cnt:
        get_cnt = cnt

    for i in range(get_cnt):
        k = "{}-{:028}".format(pfx, i)
        val = kvs.get(k.encode())[0]
        assert val is not None
        assert val.decode() == k

    with kvs.cursor(pfx.encode()) as c:
        assert sum(1 for _ in c.items()) == cnt

    with kvs.cursor(pfx.encode(), flags=hse.CursorCreateFlag.REV) as rc:
        assert sum(1 for _ in rc.items()) == cnt

    # create, seek, reads
    with kvs.cursor(pfx.encode()) as c:
        c.seek(pfx.encode())
        assert sum(1 for _ in c.items()) == cnt

    with kvs.cursor(pfx.encode(), flags=hse.CursorCreateFlag.REV) as rc:
        # Bump up the last character so prefix is larger than all keys
        ch = pfx[-1]
        i = ord(ch[0])
        i += 1
        seek_key = pfx[:-1] + chr(i)

        rc.seek(seek_key.encode())
        assert sum(1 for _ in rc.items()) == cnt


hse.init(cli.CONFIG)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext().rparams("durability.enabled=false")
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = (
            lifecycle.KvsContext(kvdb, "ptomb_cursor")
            .cparams("prefix.length=4")
            .rparams("cn_maint_disable=true")
        )
        kvs = stack.enter_context(kvs_ctx)

        # Test 1: Update after seek. Seek can be to an existing key or non-existent key
        kvs.put(b"AAAA1", b"1")
        kvdb.sync()
        kvs.prefix_delete(b"AAAA")  # kvset with only ptomb

        verify(kvs=kvs, pfx="AAAA", cnt=0)
        assert kvs.get(b"AAAA1")[0] is None

        kvdb.sync()
        verify(kvs=kvs, pfx="AAAA", cnt=0)
        assert kvs.get(b"AAAA1")[0] is None

        c = kvs.cursor(b"AAAA")
        c.seek(b"AAAA1")
        c.destroy()

        # This combination of number of keys and key length fills up almost the
        # entire wbtree (main).
        nkeys = 1767013
        nptombs = 10

        # Kvset with all ptombs < keys
        for i in range(nkeys):
            k = "CCCC-{:028}".format(i)
            kvs.put(k.encode(), k.encode())

        for i in range(nptombs):
            pfx = f"BBB{i}"
            kvs.prefix_delete(pfx.encode())

        verify(kvs=kvs, pfx="CCCC", cnt=nkeys)
        kvdb.sync()

        verify(kvs=kvs, pfx="CCCC", cnt=nkeys)

        # Kvset with all ptombs > keys
        for i in range(nkeys):
            k = "DDDD-{:028}".format(i)
            kvs.put(k.encode(), k.encode())

        for i in range(nptombs):
            pfx = f"EEE{i}"
            kvs.prefix_delete(pfx.encode())

        verify(kvs=kvs, pfx="DDDD", cnt=nkeys)
        kvdb.sync()

        verify(kvs=kvs, pfx="DDDD", cnt=nkeys)
finally:
    hse.fini()
