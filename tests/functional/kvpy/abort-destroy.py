#!/usr/bin/env python3

from hse2 import hse
from contextlib import ExitStack
from utility import lifecycle, cli

hse.init(cli.HOME)

try:
    with ExitStack() as stack:
        kvdb_ctx = lifecycle.KvdbContext()
        kvdb = stack.enter_context(kvdb_ctx)
        kvs_ctx = lifecycle.KvsContext(kvdb, "abort_destroy").rparams("transactions_enable=1")
        kvs = stack.enter_context(kvs_ctx)

        txn = kvdb.transaction()
        txn.begin()
        cursor = kvs.cursor(txn=txn)
        txn.abort()
        cursor.destroy()
finally:
    hse.fini()
