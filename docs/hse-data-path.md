<!--
SPDX-License-Identifier: Apache-2.0 OR MIT

SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.
-->

# HSE Data Path

DRAFT: This is a work in progress.

This and other markdown documents will evntually be assembled into
coherent set of architecture document.

This document will be easier to understand if you read
[hse-objects.md](hse-objects.md) first.

Operations described in this document:

- hse_kvs_get
- hse_kvs_put
- hse_kvs_delete

## hse_kvs_get

    +--------------------+
    |  API:hse_kvs_get() |
    +--------------------+
        |
        V
    +------------------------+
    |  IKVDB:ikvdb_kvs_get() |
    +------------------------+
        |
        V
    +---------------------------------------+
    |  IKVS:ikvs_get()                      |
    +---------------------------------------+
    |  Search c0:                           |
    |    if (txn)                           |
    |      A: kvdb_ctxn_get()               |
    |    else                               |
    |      get latest view seqno from KVDB  |
    |      B: C0:c0_get(view seqno)         |
    |                                       |
    |  Search cN:                           |
    |    if not found in c0:                | C       +--------------+
    |      C: CN:cn_get(view seqno)  ---------------->| CN: cn_get() |
    |                                       |         +--------------+
    +---------------------------------------+
         |B          |A
         |           |
         |           V
         |      +----------------------------+
         |      |  kvdb_ctxn_get()           |
         |      +----------------------------+
         |      |  get view seqno from txn   |
         |      |  C0:c0_get(txn view seqno) |
         |      +----------------------------+
         |           |
         |           |
         V           V
    +---------------------------------+
    |  C0:c0_get(view seqno)          |
    +---------------------------------+
    |  The kv-tuples that this query  |
    |  can see is determined by the   |
    |  view seqno.                    |
    +---------------------------------+
        |
        V
    +--------------------------------------------+
    |  C0SK:c0sk_get()                           |
    +--------------------------------------------+
    |  For each KVMS from newest to oldest:      |
    |    Ask KVMS which C0_KVSET key hashes to   |
    |    Call C0_KVSET:c0kvs_get_rcu()           |
    +--------------------------------------------+
        |
        V
    +---------------------------+
    |  C0_KVSET:c0kvs_get_rcu() |
    +---------------------------+
        |
        V
    +-------------------+
    |  BONSAI:bn_find() |
    +-------------------+

## hse_kvs_put / hse_kvs_delete

The put path is shown here.  Deletes follow a parallel path that merge in c0sk_putdel.

    +--------------------+                              +-----------------------+
    |  API:hse_kvs_put() |                              |  API:hse_kvs_delete() |
    +--------------------+                              +-----------------------+
        |                                                   |
        V                                                   V
    +------------------------+                          [ Parallel path for deletes ]
    |  IKVDB:ikvdb_kvs_put() |                              .
    +------------------------+                              .
        |
        V
    +-------------------------+
    |  IKVS:ikvs_put()        |
    +-------------------------+
    |  if (txn)               |
    |    kvdb_ctxn_put() ----------+
    |  else                   |    |
    |    C0:c0_put()          |    |
    +----|--------------------+    |
         |                         V
         |      +----------------------------+
         |      |  kvdb_ctxn_put()           |
         |      +----------------------------+
         |      |  get key lock (to detect   |
         |      |      write collisions)     |
         |      |  C0:c0_put()               |
         |      +----------------------------+
         |           |
         V           V
    +--------------------------+                            .
    |  C0:c0_put()             |                            .
    +--------------------------+                            .
        |                                                   |
        V                                                   V
    +--------------------------+                    +--------------------------+
    |  C0SK:c0sk_put()         |                    |  C0SK:c0sk_del()         |
    +--------------------------+                    +--------------------------+
        |                                                   |
        |   +-----------------------------------------------+
        |   |
        V   V
    +---------------------------------------------------+
    |  C0SK:c0sk_putdel()                               |
    +---------------------------------------------------+
    |Start:                                             |
    |  Select active (newest) KVMS:                     |
    |    Ask KVMS which C0_KVSET the key hashes to      |
    |    C0_KVSET:c0kvs_putdel()                        |
    |                                                   |
    |  If operation fails b/c KVMS or C0_KVSET is full: |
    |    freeze active KVMS and queue it for ingest     |
    |    create new active KVMS                         |
    |    goto Start                                     |
    +---------------------------------------------------+
        |
        V
    +---------------------------+
    |  C0_KVSET:c0kvs_putdel()  |
    +---------------------------+
        |
        V
    +--------------------------------+
    |  BONSAI:bn_insert_or_replace() |
    +--------------------------------+
    |  seqno assigned here           |
    +--------------------------------+

## Improvements ?
- Eliminate c0 layer
- Merge put and del path at ikvs layer (implement ikvs_put_del)
  Also eliminate split at c0kvs layer.
- Change ivks_get to get view seqno from txn and lock the txn, and
  then call c0_get directly.  Remove kvdb_ctxn_get(), reduce coupling
  (ctxn doesn't need to know about c0(?), remove double call to get
  txn view seqno when dropping into cN.


## cn_get

TODO: but here's the callstack:

    cn_get() {
        qctx.qtype = QUERY_GET;
        cn_tree_lookup(&qctx) {
            rmlock_rlock();
            node = root;
            while (node) {
                for (each kvs in node) {
                    if (qctx.QUERY_GET) {
                        kvset_lookup() {
                            kvset_lookup_vref() {
                                kvset_ptomb_lookup() {
                                    wbtr_read_vref() {
                                        wbtr_seek_page() {
                                            binary search to wbtree page;
                                        }
                                        binary search to lfe;
                                    }
                                }
                                check lcp for quick path to search;
                                check key against kvset min/max for quick exit;
                              search:
                                binary search kblocks using kblk_plausible();
                                search only one kblock w/ kblk_get_value_ref() {
                                    check bloom;
                                    wbtr_read_vref(); //-->
                                }
                                // BUG? can't more than one kblock be plausible?
                            }
                            kvset_lookup_val() {
                                use mblock read for large buffers;
                                may require use of temp buffer, which could
                                    be a tls buffer or an allocated buffer;
                                decompress if necessary;
                            }
                        }
                    } else if (qctx.QUERY_PROBE_PFX) {
                        kvset_pfx_lookup();
                    }
                    if (found)
                        goto done;
                }
                node = next node;
            }
          done:
            rmlock_runlock(lock);
        }
    }
