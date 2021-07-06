#!/usr/bin/env python3

from contextlib import ExitStack
from typing import List
from hse2 import hse

from utility import lifecycle


hse.init()

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "ten_tx").rparams("transactions_enable=1")
        kvs = stack.enter_context(kvs_ctx)

        cursor_txn = kvdb.transaction()
        cursor_txn.begin()
        holder = kvs.cursor(flags=hse.CursorFlag.BIND_TXN, txn=cursor_txn)
        rholder = kvs.cursor(
            flags=hse.CursorFlag.REVERSE | hse.CursorFlag.BIND_TXN, txn=cursor_txn
        )

        txn = kvdb.transaction()
        exp_list: List[str] = []
        for i in range(1, 11):
            txn.begin()
            k = f"0x00000001000000000000000{i:x}"
            v = f"record{i-1}"
            exp_list.append(v)
            kvs.put(k.encode(), v.encode(), txn=txn)
            kvs.put(b"updateCounter", f"{i}".encode(), txn=txn)
            kvs.put(b"deltaCounter", f"{i}".encode(), txn=txn)
            txn.commit()

        n = len(exp_list)
        exp_list.append(f"{n}")
        exp_list.append(f"{n}")

        assert sum(1 for _ in holder.items()) == 0
        assert sum(1 for _ in rholder.items()) == 0

        cursor_txn.abort()
        cursor_txn = kvdb.transaction()
        cursor_txn.begin()
        holder.update(flags=hse.CursorFlag.BIND_TXN, txn=cursor_txn)
        holder.seek(b"0")
        rholder.update(
            flags=hse.CursorFlag.REVERSE | hse.CursorFlag.BIND_TXN, txn=cursor_txn
        )
        rholder.seek(None)

        holder_values = [v.decode() for _, v in holder.items() if v]
        rholder_values = [v.decode() for _, v in rholder.items() if v]
        assert len(holder_values) == len(exp_list)
        for x, y in zip(holder_values, exp_list):
            assert x == y
        for x, y in zip(rholder_values, reversed(exp_list)):
            assert x == y

        holder.seek(b"0x000000010000000000000006")
        _, prev_value = holder.read()
        for _ in range(4):
            _, value = holder.read()
            assert prev_value
            assert value
            assert prev_value < value
            prev_value = value

        rholder.seek(b"0x000000010000000000000006")
        _, prev_value = rholder.read()
        for _ in range(4):
            _, value = rholder.read()
            assert prev_value
            assert value
            assert prev_value > value
            prev_value = value

        holder.destroy()
        rholder.destroy()
finally:
    hse.fini()
