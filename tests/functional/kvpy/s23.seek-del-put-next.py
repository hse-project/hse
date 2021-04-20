#!/usr/bin/env python3

import sys
from hse import init, fini, Kvdb

init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs23")
kvs = kvdb.kvs_open("kvs23")

kvs.put(b"a", b"1")
kvs.put(b"b", b"2")
kvs.put(b"c", b"3")

cursor = kvs.cursor()
cursor.seek(b"a")

kvs.delete(b"a")
kvs.put(b"a", b"11")

cursor.update()
kv = cursor.read()
assert kv == (b"a", b"11")

cursor.destroy()

kvs.close()
kvdb.close()
fini()
