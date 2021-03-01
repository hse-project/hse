#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs5")
    kvs = kvdb.kvs_open("kvs5")

    with kvdb.transaction() as txn:
        kvs.put(b"0x000000012b0204", b"key1", txn=txn)

    with kvdb.transaction() as txn:
        kvs.put(b"0x000000012b0404", b"key2")

    with kvdb.transaction() as txn:
        kvs.put(b"0x000000012b0604", b"key3")

    with kvs.cursor() as cur:
        cur.seek(b"0x000000012b0404")
        _, value = cur.read()

    assert value == b"key2"
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs5")
        kvdb.close()

hse.Kvdb.fini()
