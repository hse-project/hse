#!/usr/bin/env python3

import sys
from hse import Kvdb, Params

Kvdb.init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest

kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs25", params=p)
kvs = kvdb.kvs_open("kvs25", params=p)

kvs.put(b"a", b"1")

cursor = kvs.cursor()
kvdb.sync()

kv = cursor.read()
assert kv == (b"a", b"1")

cursor.read()
assert cursor.eof

cursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
