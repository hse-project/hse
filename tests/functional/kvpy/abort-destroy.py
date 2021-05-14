#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "abort_destroy", p) as kvs:
            txn = kvdb.transaction()
            txn.begin()
            cursor = kvs.cursor(txn=txn, bind_txn=True)
            txn.abort()
            cursor.destroy()
finally:
    hse.fini()
