#!/usr/bin/env python3
from contextlib import ExitStack

import hse
from hse import experimental as hse_exp

import util


hse.init()

try:
    p = hse.Params()

    with util.create_kvdb(util.get_kvdb_name(), p) as kvdb:
        p.set(key="kvs.pfx_len", value="2")
        p.set(key="kvs.sfx_len", value="1")

        with ExitStack() as kvs_stack:
            p.set(key="kvs.transactions_enable", value="0")
            kvs = kvs_stack.enter_context(util.create_kvs(kvdb, "kvs37-non_txn", p))

            p.set(key="kvs.transactions_enable", value="1")
            kvs_tx = kvs_stack.enter_context(util.create_kvs(kvdb, "kvs37-txn", p))

            '''
             +--------------------+---------------+-------------+
             |                    |  Txn kvs      | Non-Txn kvs |
             +--------------------+---------------+-------------+
             |  txn read          |    Yes        |    No       |
             +--------------------+---------------+-------------+
             |  txn write         |    Yes        |    No       |
             +--------------------+---------------+-------------+
             |  non-txn read      |    Yes        |    Yes      |
             +--------------------+---------------+-------------+
             |  non-txn write     |    No         |    Yes      |
             +--------------------+---------------+-------------+
            '''

            #
            # Part 1: Non-Txn KVS
            #

            # non-txn kvs and non-txn write: allowed
            kvs.put(b'ab1', b'1')
            kvs.put(b'ab2', b'1')
            kvs.put(b'ab3', b'1')
            kvs.put(b'ab4', b'1')
            kvs.put(b'ab5', b'1')
            kvs.put(b'ab6', b'1')

            kvs.delete(b'ab4')
            kvs.delete(b'ab5')
            kvs.delete(b'ab6')

            # non-txn kvs and non-txn read: allowed
            assert kvs.get(b'ab1') == b'1'
            assert kvs.get(b'ab2') == b'1'
            assert kvs.get(b'ab3') == b'1'
            assert kvs.get(b'ab4') is None
            assert kvs.get(b'ab5') is None
            assert kvs.get(b'ab6') is None

            cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"ab")
            assert cnt == hse_exp.KvsPfxProbeCnt.MUL

            with kvs.cursor() as cur:
                assert sum(1 for _ in cur.items()) == 3

            # non-txn kvs and txn write: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.put(b'ab1', b'2', txn=t)
                assert False
            except hse.KvdbException:
                pass

            # non-txn kvs and txn read: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.get(b'ab1', txn=t)
                assert False
            except hse.KvdbException:
                pass

            try:
                with kvdb.transaction() as t:
                    cnt, *_ = hse_exp.kvs_prefix_probe(kvs, b"ab", txn=t)
                assert False
            except hse.KvdbException:
                pass

            try:
                with kvdb.transaction() as t:
                    with kvs.cursor(bind_txn=True, txn=t) as cur:
                        assert sum(1 for _ in cur.items()) == 3
                assert False
            except hse.KvdbException:
                pass

            # non-txn kvs and txn delete: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.delete(b'ab1', txn=t)
                assert False
            except hse.KvdbException:
                pass

            #
            # Part 2: Txn KVS
            #

            with kvdb.transaction() as t:
                # txn kvs and txn write: allowed
                kvs_tx.put(b'ab1', b'1', txn=t)
                kvs_tx.put(b'ab2', b'1', txn=t)
                kvs_tx.put(b'ab3', b'1', txn=t)
                kvs_tx.put(b'ab4', b'1', txn=t)
                kvs_tx.put(b'ab5', b'1', txn=t)
                kvs_tx.put(b'ab6', b'1', txn=t)

                kvs_tx.delete(b'ab4', txn=t)
                kvs_tx.delete(b'ab5', txn=t)
                kvs_tx.delete(b'ab6', txn=t)

                # txn kvs and txn read: allowed
                assert kvs_tx.get(b'ab1', txn=t) == b'1'
                assert kvs_tx.get(b'ab2', txn=t) == b'1'
                assert kvs_tx.get(b'ab3', txn=t) == b'1'

                cnt, *_ = hse_exp.kvs_prefix_probe(kvs_tx, b"ab", txn=t)
                assert cnt == hse_exp.KvsPfxProbeCnt.MUL

                with kvs_tx.cursor(bind_txn=True, txn=t) as cur:
                    assert sum(1 for _ in cur.items()) == 3

            # txn kvs and non-txn read: allowed
            assert kvs_tx.get(b'ab1') == b'1'
            assert kvs_tx.get(b'ab2') == b'1'
            assert kvs_tx.get(b'ab3') == b'1'

            cnt, *_ = hse_exp.kvs_prefix_probe(kvs_tx, b"ab")
            assert cnt == hse_exp.KvsPfxProbeCnt.MUL

            with kvs_tx.cursor() as cur:
                assert sum(1 for _ in cur.items()) == 3

            # txn kvs and non-txn write: not allowed
            try:
                kvs_tx.put(b'ab1', b'2')
                assert False
            except hse.KvdbException:
                pass

            # txn kvs and non-txn delete: not allowed
            try:
                kvs_tx.delete(b'ab1')
                assert False
            except hse.KvdbException:
                pass

            #
            # Part 3: Prefix deletes
            #

            p.set(key="kvs.transactions_enable", value="0")
            kvs = kvs_stack.enter_context(util.create_kvs(kvdb, "kvs37-non_txn-2", p))

            kvs.put(b'aa1', b'1')
            kvs.put(b'aa2', b'1')

            assert kvs.get(b'aa1') == b'1'
            assert kvs.get(b'aa2') == b'1'

            # non-txn kvs and non-txn prefix delete: allowed
            kvs.prefix_delete(b'aa')
            assert kvs.get(b'aa1') is None
            assert kvs.get(b'aa2') is None

            kvs.put(b'aa1', b'1')
            kvs.put(b'aa2', b'1')

            # non-txn kvs and txn prefix delete: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.prefix_delete(b'aa', txn=t)
                assert False
            except hse.KvdbException:
                pass

            # Cleanup
            kvs.prefix_delete(b'aa')
            assert kvs.get(b'aa1') is None
            assert kvs.get(b'aa2') is None

            p.set(key="kvs.transactions_enable", value="1")
            kvs_tx = kvs_stack.enter_context(util.create_kvs(kvdb, "kvs37-txn-2", p))

            # txn kvs and txn prefix delete: allowed
            with kvdb.transaction() as t:
                kvs_tx.prefix_delete(b'aa', txn=t)
                assert kvs.get(b'aa1') is None
                assert kvs.get(b'aa2') is None

            kvs.put(b'aa1', b'1')
            kvs.put(b'aa2', b'1')

            # txn kvs and non-txn prefix delete: not allowed
            try:
                kvs_tx.prefix_delete(b'aa')
                assert False
            except hse.KvdbException:
                pass
finally:
    hse.fini()
