#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bind_commited", p) as kvs:
            txn = kvdb.transaction()
            txn.begin()

            txcursor = kvs.cursor(txn=txn, bind_txn=True)
            kvs.put(b"a", b"1", txn=txn)
            kvs.put(b"b", b"2", txn=txn)
            kvs.put(b"c", b"3", txn=txn)
            kv = txcursor.read()
            assert kv == (b"a", b"1")

            txn.commit()
            txn.begin()
            txcursor.update(txn=txn, bind_txn=True)
            kvs.put(b"a", b"12", txn=txn)
            kvs.put(b"b", b"22", txn=txn)
            kvs.put(b"c", b"32", txn=txn)

            kv = txcursor.read()
            assert kv == (b"b", b"22")
            kv = txcursor.read()
            assert kv == (b"c", b"32")

            with kvdb.transaction() as t:
                cursor = kvs.cursor(txn=t, bind_txn=t)
                kv = cursor.read()
                assert kv == (b"a", b"1")
                kv = cursor.read()
                assert kv == (b"b", b"2")
                kv = cursor.read()
                assert kv == (b"c", b"3")
                cursor.read()
                assert cursor.eof
                cursor.destroy()

            txcursor.seek(b"0")
            kv = txcursor.read()
            assert kv == (b"a", b"12")
            kv = txcursor.read()
            assert kv == (b"b", b"22")
            kv = txcursor.read()
            assert kv == (b"c", b"32")
            txcursor.read()
            assert txcursor.eof

            txcursor.destroy()
finally:
    hse.fini()
