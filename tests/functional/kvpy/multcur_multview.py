#!/usr/bin/env python3

from contextlib import ExitStack
import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "multicur_multiview")
        kvs = stack.enter_context(kvs_ctx)

        kvs.put(b"0x0001", b"0x0001")
        ca = kvs.cursor()

        kvs.put(b"0x0010", b"0x0010")
        cb = kvs.cursor()

        kvs.put(b"0x0002", b"0x0002")
        cc = kvs.cursor()

        kvs.put(b"0xff00", b"0xff00")
        cd = kvs.cursor()

        kvs.put(b"0x000f", b"0x000f")
        kvs.put(b"0x0006", b"0x0006")
        kvs.put(b"0x0003", b"0x0003")
        ce = kvs.cursor()

        kvs.put(b"0x0004", b"0x0004")

        ca_count = sum(1 for _ in ca.items())
        cb_count = sum(1 for _ in cb.items())
        cc_count = sum(1 for _ in cc.items())
        cd_count = sum(1 for _ in cd.items())
        ce_count = sum(1 for _ in ce.items())
        assert ca_count < cb_count < cc_count < cd_count < ce_count

        ca.update_view()
        ca.seek(b"0x00")
        ca_count_v2 = sum(1 for _ in ca.items())
        assert ca_count_v2 != ca_count

        ca.seek(b"0x0006")
        ca_count_v3 = sum(1 for _ in ca.items())
        assert ca_count_v3 != ca_count_v2 != ca_count

        ca.destroy()
        cb.destroy()
        cc.destroy()
        cd.destroy()
        ce.destroy()
finally:
    hse.fini()
