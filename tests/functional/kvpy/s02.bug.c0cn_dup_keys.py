#!/usr/bin/env python3

import sys
import hse


hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs2")
    kvs = kvdb.kvs_open("kvs2")

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
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs2")
        kvdb.close()
