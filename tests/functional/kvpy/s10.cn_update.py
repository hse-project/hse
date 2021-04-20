#!/usr/bin/env python3

import sys
import hse


hse.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs10")
    kvs = kvdb.kvs_open("kvs10")

    kvs.put(b"a", b"1")
    kvs.put(b"b", b"2")
    kvs.put(b"c", b"3")

    cur = kvs.cursor()
    assert sum(1 for _ in cur.items()) == 3

    kvdb.sync()

    kvs.put(b"d", b"4")
    kvs.put(b"e", b"5")
    kvs.put(b"a", b"100")

    cur.update()
    assert sum(1 for _ in cur.items()) == 2  # keys beyond 'c' = 'd' and 'e'
    cur.seek(b"0x0")
    assert sum(1 for _ in cur.items()) == 5

    cur.destroy()
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs10")
        kvdb.close()

hse.fini()
