#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "cn_seqno", p) as kvs:
            txn = kvdb.transaction()
            txn.begin()

            with kvdb.transaction() as t:
                kvs.put(b"a", b"1", txn=t)

            kvdb.sync()

            txcursor = kvs.cursor(txn=txn, bind_txn=True)
            txcursor.read()
            assert txcursor.eof

            txn.abort()
            txcursor.seek(b"0")
            kv = txcursor.read()
            assert not txcursor.eof
            assert kv == (b"a", b"1")

            txcursor.destroy()
finally:
    hse.fini()
