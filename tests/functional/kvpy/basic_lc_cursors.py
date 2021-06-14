#!/usr/bin/env python3
'''
A basic test fo lc cursors
There's uncommitted data in two transactions and while the transactions are live, sync
is called. This moves the data to LC. Then cursors are used to read data from LC.
'''
from contextlib import ExitStack

import hse

import util

def run_test(kvdb, kvs):
    with kvdb.transaction() as t5:
        kvs.put(b"ab1", b"val1", txn=t5)
        kvs.put(b"ab2", b"val2", txn=t5)
        kvs.put(b"ab3", b"val3", txn=t5)

    t0 = kvdb.transaction()
    t0.begin()
    t1 = kvdb.transaction()
    t1.begin()

    kvs.put(b"aa1", b"uncommitted-aa1", txn=t0) # commit
    kvs.put(b"aa2", b"uncommitted-aa2", txn=t0) # commit
    kvs.put(b"aa3", b"uncommitted-aa3", txn=t1) # abort

    val = kvs.get(b"aa1", txn=t0)
    assert val == b"uncommitted-aa1"

    with kvs.cursor(reverse=False, txn=t0, bind_txn=True) as c:
        assert sum(1 for _ in c.items()) == 5

        c.seek(b"aa2")
        kv = c.read()
        assert kv == (b'aa2', b'uncommitted-aa2')
        kv = c.read()
        assert kv == (b'ab1', b'val1')
        kv = c.read()
        assert kv == (b'ab2', b'val2')
        kv = c.read()
        assert kv == (b'ab3', b'val3')
        c.read()
        assert c.eof

        c.seek(b"ab2")
        kv = c.read()
        assert kv == (b'ab2', b'val2')
        kv = c.read()
        assert kv == (b'ab3', b'val3')
        c.read()
        assert c.eof

    with kvs.cursor(reverse=True, txn=t0, bind_txn=True) as c:
        assert sum(1 for _ in c.items()) == 5

        c.seek(b"aa2")
        kv = c.read()
        assert kv == (b'aa2', b'uncommitted-aa2')
        kv = c.read()
        assert kv == (b'aa1', b'uncommitted-aa1')
        c.read()
        assert c.eof

        c.seek(b"ab2")
        kv = c.read()
        assert kv == (b'ab2', b'val2')
        kv = c.read()
        assert kv == (b'ab1', b'val1')
        kv = c.read()
        assert kv == (b'aa2', b'uncommitted-aa2')
        kv = c.read()
        assert kv == (b'aa1', b'uncommitted-aa1')
        c.read()
        assert c.eof

    kvdb.sync()

    # Get from C0
    with kvdb.transaction() as t5:
        val = kvs.get(b"ab3", txn=t5)
        assert val == b"val3"

    # Get from LC
    val = kvs.get(b"aa1", txn=t0)
    assert val == b"uncommitted-aa1" # uncommitted data from current txn
    val = kvs.get(b"aa3", txn=t0)
    assert val == None # uncommitted data from some other txn
    val = kvs.get(b"aa3", txn=t1)
    assert val == b"uncommitted-aa3" # uncommitted data from current txn

    t0.commit()
    t1.abort()

    kvdb.sync()

    # Get from CN. Keys were previously in LC.
    with kvdb.transaction() as t5:
        # Committed. Should be visible
        val = kvs.get(b"aa1", txn=t5)
        assert val == b"uncommitted-aa1"

        # Aborted. Should not see this key.
        val = kvs.get(b"aa3", txn=t5)
        assert val == None
    pass

hse.init()
try:
    p = hse.Params()
    p.set(key="kvdb.dur_enable", value="0")  # So sync forces an ingest
    p.set(key="kvs.transactions_enable", value="1")

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        with ExitStack() as kvs_stack:
            kvs = kvs_stack.enter_context(util.create_kvs(kvdb, "basic_lc", p))
            run_test(kvdb, kvs)

finally:
    hse.fini()


