#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs3")
    kvs = kvdb.kvs_open("kvs3")

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

    ca.update()
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
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs3")
        kvdb.close()

hse.Kvdb.fini()
