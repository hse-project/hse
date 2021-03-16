#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

kvdb = hse.Kvdb.open(sys.argv[1])
kvdb.kvs_make("kvs1")
kvs = kvdb.kvs_open("kvs1")

kvs.put(b"key1", b"1")
kvs.put(b"key2", b"1")
kvs.put(b"key3", b"1")
kvs.put(b"key4", b"1")
kvs.put(b"key5", b"1")
kvs.put(b"key6", b"1")
kvs.put(b"key7", b"1")
kvs.put(b"key8", b"1")
kvs.put(b"key9", b"1")

c = kvs.cursor(reverse=False)
kv = c.read()
print(kv)
kv = c.read()
print(kv)

c.seek(b"key3")

kvs.delete(b'key3')

v = kvs.get(b'key3')
print(v)
c.update(reverse=False)
kv = c.read()
print(kv)

c.destroy()
kvs.close()
kvdb.close()
