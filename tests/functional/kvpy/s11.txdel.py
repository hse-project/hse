#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs11")
    p = hse.Params()
    p.set(key="kvs.enable_transactions", value="1")
    kvs = kvdb.kvs_open("kvs11", params=p)

    with kvdb.transaction() as txn:
        kvs.put(b"pfx.a", b"1", txn=txn)
        kvs.put(b"pfx.b", b"2", txn=txn)
        kvs.put(b"pfx.c", b"3", txn=txn)

    with kvdb.transaction() as txn:
        with kvs.cursor(b"pfx", txn=txn, bind_txn=True) as cur:
            kv = cur.read()
            assert kv == (b"pfx.a", b"1")
            kv = cur.read()
            assert kv == (b"pfx.b", b"2")
            kv = cur.read()
            assert kv == (b"pfx.c", b"3")
            cur.read()
            assert cur.eof

    with kvdb.transaction() as txn:
        kvs.delete(b"pfx.c", txn=txn)

    with kvdb.transaction() as txn:
        with kvs.cursor(b"pfx", txn=txn, bind_txn=True) as cur:
            kv = cur.read()
            assert kv == (b"pfx.a", b"1")
            kv = cur.read()
            assert kv == (b"pfx.b", b"2")
            cur.read()
            assert cur.eof
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.close()

hse.Kvdb.fini()
