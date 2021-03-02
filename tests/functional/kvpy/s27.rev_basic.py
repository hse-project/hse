#!/usr/bin/env python3

import sys
from hse import Kvdb

Kvdb.init()

kvdb = Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs27")
kvs = kvdb.kvs_open("kvs27")

kvs.put(b"a", b"1")
kvs.put(b"b", b"2")
assert kvs.get(b"a") == b"1"
assert kvs.get(b"b") == b"2"

cursor = kvs.cursor(reverse=True)
kv = cursor.read()
assert kv == (b"b", b"2")
kv = cursor.read()
assert kv == (b"a", b"1")
cursor.read()
assert cursor.eof

cursor.seek(b"b")
kv = cursor.read()
assert kv == (b"b", b"2")

cursor.seek(b"a")
kv = cursor.read()
assert kv == (b"a", b"1")

cursor.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
