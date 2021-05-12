#!/usr/bin/env python3
import hse

import util


hse.init()

try:
    p = hse.Params()
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with util.create_kvs(kvdb, "bind", p) as kvs1, util.create_kvs(
            kvdb, "bind-2", params=p
        ) as kvs2:
            with kvdb.transaction() as txn:
                kvs1.put(b"a", b"1", txn=txn)
                kvs1.put(b"b", b"1", txn=txn)
                kvs1.put(b"c", b"1", txn=txn)

            with kvdb.transaction() as txn:
                kvs2.put(b"a", b"2", txn=txn)
                kvs2.put(b"b", b"2", txn=txn)
                kvs2.put(b"c", b"2", txn=txn)

            with kvdb.transaction() as txn:
                cursor = kvs1.cursor(bind_txn=True, txn=txn)

                kv = cursor.read()
                assert kv == (b"a", b"1")
                kv = cursor.read()
                assert kv == (b"b", b"1")
                kv = cursor.read()
                assert kv == (b"c", b"1")
                cursor.read()
                assert cursor.eof

                kvs1.put(b"d", b"1", txn=txn)
                cursor.seek(b"d")
                cursor.update(bind_txn=True, txn=txn)

                cursor.seek(b"d")
                kv = cursor.read()
                assert kv == (b"d", b"1")

                txn.abort()
                cursor.seek(b"a")
                try:
                    cursor.read()
                    assert False
                except:
                    pass

                cursor.destroy()

            txn = kvdb.transaction()
            txn.begin()
            kvs2.put(b"d", b"2", txn=txn)

            cursor1 = kvs2.cursor(bind_txn=True, txn=txn)
            cursor1.seek(b"d")
            kv = cursor1.read()
            assert kv == (b"d", b"2")
            cursor1.read()
            assert cursor1.eof
            txn.commit()

            with kvdb.transaction() as t:
                cursor2 = kvs2.cursor(bind_txn=True, txn=t)
                for k, v in cursor2.items():
                    assert v == b"2"
                try:
                    cursor1.read()
                    assert False
                except:
                    pass
                cursor2.destroy()

            cursor1.destroy()
finally:
    hse.fini()
