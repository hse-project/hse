#!/usr/bin/env python3

import sys
import hse

hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs4")
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")
    kvs = kvdb.kvs_open("kvs4", params=p)

    with kvdb.transaction() as txn:
        kvs.put(b"0x000000012b0204", b"key1", txn=txn)
        kvs.put(b"0x000000012b0404", b"key2", txn=txn)
        kvs.put(b"0x000000012b0604", b"key3", txn=txn)

        with kvs.cursor(b"0x00000001", bind_txn=True, txn=txn) as cur:
            cur.read()
            cur.read()
            cur.read()

            cur.read()
            assert cur.eof
finally:
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs4")
        kvdb.close()

hse.Kvdb.fini()
