#!/usr/bin/env python3

import sys
from hse import Kvdb, Params

Kvdb.init()

p = Params()
p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest
p.set(key="kvs.pfx_len", value="3")

# Test 1: Update after seek. Seek can be to an existing key or non-existent key
kvdb = Kvdb.open(sys.argv[1], params=p)
kvdb.kvs_make("kvs36", params=p)
kvs = kvdb.kvs_open("kvs36", params=p)

kvs.prefix_delete(b"key")
kvs.put(b"key1", b"val1")
kvs.put(b"key2", b"val1")
kvs.put(b"key3", b"val1")
kvs.put(b"key4", b"val1")

with kvs.cursor() as c:
    kv = c.read()
    assert kv == (b"key1", b"val1")
    kv = c.read()
    assert kv == (b"key2", b"val1")

    c.update()
    kv = c.read()
    assert kv == (b"key3", b"val1")

    c.seek(b"key2")
    c.update()
    kv = c.read()
    assert kv == (b"key2", b"val1")

kvs.prefix_delete(b"key")
kvs.put(b"key1", b"val2")
kvs.put(b"key2", b"val2")
kvs.put(b"key3", b"val2")
kvs.put(b"key4", b"val2")

with kvs.cursor() as c:
    kv = c.read()
    assert kv == (b"key1", b"val2")
    kv = c.read()
    assert kv == (b"key2", b"val2")

    kvs.prefix_delete(b"key")
    kvs.put(b"key3", b"val3")
    kvs.put(b"key4", b"val3")

    c.update()
    kv = c.read()
    assert kv == (b"key3", b"val3")

    c.seek(b"key2")
    c.update()
    kv = c.read()
    assert kv == (b"key3", b"val3")

c.destroy()

kvs.close()
kvdb.close()
Kvdb.fini()
