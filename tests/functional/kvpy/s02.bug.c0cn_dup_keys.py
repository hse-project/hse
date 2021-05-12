#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "c0cn_dup_keys", p) as kvs:
            kvs.put(b"0x0001", b"0x0001")
            kvs.put(b"0x0010", b"0x0010")
            kvs.put(b"0x0002", b"0x0002")
            kvs.put(b"0xff00", b"0xff00")
            kvs.put(b"0x000f", b"0x000f")
            kvs.put(b"0x0006", b"0x0006")
            kvs.put(b"0x0003", b"0x0003")
            kvs.put(b"0x0004", b"0x0004")

            cur = kvs.cursor()
            count = sum(1 for _ in cur.items())
            assert count == 8
            cur.destroy()

            cur = kvs.cursor(b"0x00")
            count = sum(1 for _ in cur.items())
            assert count == 7
            cur.destroy()

            cur = kvs.cursor(b"0xff")
            count = sum(1 for _ in cur.items())
            assert count == 1
            cur.destroy()
finally:
    hse.fini()
