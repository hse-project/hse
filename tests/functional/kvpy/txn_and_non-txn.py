#!/usr/bin/env python3

from typing import Tuple

import hse

from utility import lifecycle


hse.init()

KVS_CPARAMS: Tuple[str, ...] = ("pfx_len=2", "sfx_len=1")

try:
    with lifecycle.KvdbContext() as kvdb:
        #
        # Part 1: Non-Txn KVS
        #
        with lifecycle.KvsContext(kvdb, "kvs37-non_txn").rparams(
            "transactions_enable=0"
        ).cparams(*KVS_CPARAMS) as kvs:
            """
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
            """

            # non-txn kvs and non-txn write: allowed
            kvs.put(b"ab1", b"1")
            kvs.put(b"ab2", b"1")
            kvs.put(b"ab3", b"1")
            kvs.put(b"ab4", b"1")
            kvs.put(b"ab5", b"1")
            kvs.put(b"ab6", b"1")

            kvs.delete(b"ab4")
            kvs.delete(b"ab5")
            kvs.delete(b"ab6")

            # non-txn kvs and non-txn read: allowed
            assert kvs.get(b"ab1") == b"1"
            assert kvs.get(b"ab2") == b"1"
            assert kvs.get(b"ab3") == b"1"
            assert kvs.get(b"ab4") is None
            assert kvs.get(b"ab5") is None
            assert kvs.get(b"ab6") is None

            cnt, *_ = kvs.prefix_probe(b"ab")
            assert cnt == hse.KvsPfxProbeCnt.MUL

            with kvs.cursor() as cur:
                assert sum(1 for _ in cur.items()) == 3

            # non-txn kvs and txn write: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.put(b"ab1", b"2", txn=t)
                assert False
            except hse.KvdbException:
                pass

            # non-txn kvs and txn read: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.get(b"ab1", txn=t)
                assert False
            except hse.KvdbException:
                pass

            try:
                with kvdb.transaction() as t:
                    cnt, *_ = kvs.prefix_probe(b"ab", txn=t)
                assert False
            except hse.KvdbException:
                pass

            try:
                with kvdb.transaction() as t:
                    with kvs.cursor(flags=hse.CursorFlag.BIND_TXN, txn=t) as cur:
                        assert sum(1 for _ in cur.items()) == 3
                assert False
            except hse.KvdbException:
                pass

            # non-txn kvs and txn delete: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.delete(b"ab1", txn=t)
                assert False
            except hse.KvdbException:
                pass

        #
        # Part 2: Txn KVS
        #
        with lifecycle.KvsContext(kvdb, "kvs37-txn").rparams(
            "transactions_enable=1"
        ).cparams(*KVS_CPARAMS) as kvs_tx:
            with kvdb.transaction() as t:
                # txn kvs and txn write: allowed
                kvs_tx.put(b"ab1", b"1", txn=t)
                kvs_tx.put(b"ab2", b"1", txn=t)
                kvs_tx.put(b"ab3", b"1", txn=t)
                kvs_tx.put(b"ab4", b"1", txn=t)
                kvs_tx.put(b"ab5", b"1", txn=t)
                kvs_tx.put(b"ab6", b"1", txn=t)

                kvs_tx.delete(b"ab4", txn=t)
                kvs_tx.delete(b"ab5", txn=t)
                kvs_tx.delete(b"ab6", txn=t)

                # txn kvs and txn read: allowed
                assert kvs_tx.get(b"ab1", txn=t) == b"1"
                assert kvs_tx.get(b"ab2", txn=t) == b"1"
                assert kvs_tx.get(b"ab3", txn=t) == b"1"

                cnt, *_ = kvs_tx.prefix_probe(b"ab", txn=t)
                assert cnt == hse.KvsPfxProbeCnt.MUL

                with kvs_tx.cursor(flags=hse.CursorFlag.BIND_TXN, txn=t) as cur:
                    assert sum(1 for _ in cur.items()) == 3

            # txn kvs and non-txn read: allowed
            assert kvs_tx.get(b"ab1") == b"1"
            assert kvs_tx.get(b"ab2") == b"1"
            assert kvs_tx.get(b"ab3") == b"1"

            cnt, *_ = kvs_tx.prefix_probe(b"ab")
            assert cnt == hse.KvsPfxProbeCnt.MUL

            with kvs_tx.cursor() as cur:
                assert sum(1 for _ in cur.items()) == 3

            # txn kvs and non-txn write: not allowed
            try:
                kvs_tx.put(b"ab1", b"2")
                assert False
            except hse.KvdbException:
                pass

            # txn kvs and non-txn delete: not allowed
            try:
                kvs_tx.delete(b"ab1")
                assert False
            except hse.KvdbException:
                pass

        #
        # Part 3: Prefix deletes
        #
        with lifecycle.KvsContext(kvdb, "kvs37-non_txn-2").rparams(
            "transactions_enable=0"
        ).cparams(*KVS_CPARAMS) as kvs:
            kvs.put(b"aa1", b"1")
            kvs.put(b"aa2", b"1")

            assert kvs.get(b"aa1") == b"1"
            assert kvs.get(b"aa2") == b"1"

            # non-txn kvs and non-txn prefix delete: allowed
            kvs.prefix_delete(b"aa")
            assert kvs.get(b"aa1") is None
            assert kvs.get(b"aa2") is None

            kvs.put(b"aa1", b"1")
            kvs.put(b"aa2", b"1")

            # non-txn kvs and txn prefix delete: not allowed
            try:
                with kvdb.transaction() as t:
                    kvs.prefix_delete(b"aa", txn=t)
                assert False
            except hse.KvdbException:
                pass

            # Cleanup
            kvs.prefix_delete(b"aa")
            assert kvs.get(b"aa1") is None
            assert kvs.get(b"aa2") is None

        with lifecycle.KvsContext(kvdb, "kvs37-txn-2").rparams(
            "transactions_enable=1"
        ).cparams(*KVS_CPARAMS) as kvs_tx:
            # txn kvs and txn prefix delete: allowed
            with kvdb.transaction() as t:
                kvs_tx.put(b"aa1", b"1", txn=t)
                kvs_tx.put(b"aa2", b"1", txn=t)

            with kvdb.transaction() as t:
                kvs_tx.prefix_delete(b"aa", txn=t)

            assert kvs_tx.get(b"aa1") is None
            assert kvs_tx.get(b"aa2") is None

            with kvdb.transaction() as t:
                kvs_tx.put(b"aa1", b"1", txn=t)
                kvs_tx.put(b"aa2", b"1", txn=t)

            # txn kvs and non-txn prefix delete: not allowed
            try:
                kvs_tx.prefix_delete(b"aa")
                assert False
            except hse.KvdbException:
                pass
finally:
    hse.fini()
