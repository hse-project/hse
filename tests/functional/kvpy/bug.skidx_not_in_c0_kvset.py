#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bug_skidx_not_in_c0_kvset", p) as kvs:
            with kvdb.transaction() as txn:
                kvs.put(b"0x000000012b0204", b"key1", txn=txn)

            with kvdb.transaction() as txn:
                kvs.put(b"0x000000012b0404", b"key2", txn=txn)

            with kvdb.transaction() as txn:
                kvs.put(b"0x000000012b0604", b"key3", txn=txn)

            with kvdb.transaction() as txn:
                with kvs.cursor(bind_txn=True, txn=txn) as cur:
                    cur.seek(b"0x000000012b0404")
                    _, value = cur.read()

                assert value == b"key2"
finally:
    hse.fini()
