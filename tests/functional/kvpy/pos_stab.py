#!/usr/bin/env python3

import hse

from utility import lifecycle


hse.init()

try:
    with lifecycle.KvdbContext().rparams("dur_enable=0") as kvdb:
        # Test 1: Update after seek. Seek can be to an existing key or non-existent key
        with lifecycle.KvsContext(kvdb, "pos_stab-1") as kvs:
            kvs.put(b"a", b"1")
            kvs.put(b"b", b"2")
            kvs.put(b"d", b"4")
            kvs.put(b"e", b"5")

            cursor = kvs.cursor()

            # seek to an existing key and update.
            cursor.seek(b"b")
            cursor.update()
            kv = cursor.read()
            assert kv == (b"b", b"2")

            # seek to a non-existent key and update.
            cursor.seek(b"c")
            kvs.put(b"c", b"3")
            cursor.update()

            kv = cursor.read()
            assert kv == (b"d", b"4")
            cursor.destroy()

        # Test 2: Read keys across c0/cn
        with lifecycle.KvsContext(kvdb, "pos_stab-2") as kvs:
            kvs.put(b"ab1", b"1")
            kvdb.sync()
            kvs.put(b"ab2", b"2")
            kvdb.sync()

            # Forward cursor
            cursor = kvs.cursor(filt=b"ab")
            kv = cursor.read()
            assert kv == (b"ab1", b"1")

            kvs.put(b"ab1", b"2")

            cursor.update()
            kv = cursor.read()
            assert kv == (b"ab2", b"2")
            cursor.read()
            assert cursor.eof
            cursor.destroy()

            # Reverse cursor
            cursor = kvs.cursor(filt=b"ab", flags=hse.CursorFlag.REVERSE)
            kv = cursor.read()
            assert kv == (b"ab2", b"2")

            kvs.put(b"ab2", b"3")

            cursor.update(flags=hse.CursorFlag.REVERSE)
            kv = cursor.read()
            assert kv == (b"ab1", b"2")
            cursor.read()
            assert cursor.eof
            cursor.destroy()

        # Test 3: Read keys across c0/cn, with key update.
        with lifecycle.KvsContext(kvdb, "pos_stab-3").cparams("pfx_len=1").rparams(
            "transactions_enable=1"
        ) as kvs:
            with kvdb.transaction() as txn:
                kvs.put(b"a1a", b"1", txn=txn)
                kvs.put(b"a1b", b"2", txn=txn)
                kvs.put(b"a1c", b"3", txn=txn)
            kvdb.sync()

            with kvdb.transaction() as txn:
                kvs.put(b"a1b", b"4", txn=txn)

            read_txn = kvdb.transaction()
            read_txn.begin()
            cursor = kvs.cursor(txn=read_txn, flags=hse.CursorFlag.BIND_TXN)
            cursor.seek(b"a1b")
            kv = cursor.read()
            assert kv == (b"a1b", b"4")

            revcursor = kvs.cursor(
                txn=read_txn, flags=hse.CursorFlag.REVERSE | hse.CursorFlag.BIND_TXN
            )
            revcursor.seek(b"a1b")
            kv = revcursor.read()
            assert kv == (b"a1b", b"4")
            read_txn.abort()

            kvdb.sync()

            txn = kvdb.transaction()
            txn.begin()
            cursor.update(txn=txn, flags=hse.CursorFlag.BIND_TXN)
            cursor.update(txn=txn, flags=hse.CursorFlag.BIND_TXN)
            cursor.update(txn=txn, flags=hse.CursorFlag.BIND_TXN)
            revcursor.update(
                txn=txn, flags=hse.CursorFlag.REVERSE | hse.CursorFlag.BIND_TXN
            )
            revcursor.update(
                txn=txn, flags=hse.CursorFlag.REVERSE | hse.CursorFlag.BIND_TXN
            )
            revcursor.update(
                txn=txn, flags=hse.CursorFlag.REVERSE | hse.CursorFlag.BIND_TXN
            )

            kv = cursor.read()
            assert kv == (b"a1c", b"3")
            kv = revcursor.read()
            assert kv == (b"a1a", b"1")

            cursor.destroy()
            revcursor.destroy()
finally:
    hse.fini()
