#!/usr/bin/env python3

import sys
import hse


hse.Kvdb.init()

try:
    kvdb = hse.Kvdb.open(sys.argv[1])
    kvdb.kvs_make("kvs6")
    kvs = kvdb.kvs_open("kvs6")

    holder = kvs.cursor()
    rholder = kvs.cursor(reverse=True)

    txn = kvdb.transaction()
    exp_list = []
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

    holder.update()
    holder.seek(b"0")
    rholder.update(reverse=True)
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
    if kvs:
        kvs.close()
    if kvdb:
        kvdb.kvs_drop("kvs6")
        kvdb.close()

hse.Kvdb.fini()
