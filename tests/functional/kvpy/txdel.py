#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "txdel", p) as kvs:
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
    hse.fini()
