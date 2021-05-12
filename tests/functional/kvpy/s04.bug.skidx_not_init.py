#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bug_skidx_not_init", p) as kvs:
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
    hse.fini()
