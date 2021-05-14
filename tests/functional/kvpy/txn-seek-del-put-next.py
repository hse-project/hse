#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "txn_seek_del_put_next", p) as kvs:
            with kvdb.transaction() as txn:
                kvs.put(b"a", b"1", txn=txn)
                kvs.put(b"b", b"2", txn=txn)
                kvs.put(b"c", b"3", txn=txn)

            with kvdb.transaction() as txn:
                txcursor = kvs.cursor(txn=txn, bind_txn=True)
                txcursor.seek(b"a")
                kvs.delete(b"a", txn=txn)

            with kvdb.transaction() as txn:
                kvs.put(b"a", b"11", txn=txn)

            with kvdb.transaction() as txn:
                txcursor.update(bind_txn=True, txn=txn)
                txcursor.seek(b"a")
                kv = txcursor.read()
                assert kv == (b"a", b"11")

                txcursor.destroy()
finally:
    hse.fini()
