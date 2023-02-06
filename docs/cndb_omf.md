<!--
SPDX-License-Identifier: Apache-2.0 OR MIT

SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
-->

DRAFT!!! DRAFT!!! DRAFT!!! DRAFT!!! DRAFT!!! DRAFT!!!

# OMF descriptions

Describes the proposed CNDB OMF for HSE-3.0.

## Record types

Each record type contains a header at the beginning. This header contains the type of the record and
its size. This header is not listed in the following breakdown of the various record types.

### Version

- Magic: A magic number to verify that the MDC is a CNDB MDC.
- Version: Version of the CNDB OMF.
- Captgt: (Capacity Target) Size of the CNDB.

### KVS_CREATE

- Create-time parameters for a KVS.
  - Prefix length: Length of prefixes when using prefix delete.
- Flags: Flags for the KVS.
  - `CN_CFLAG_CAPPED`: Whether or not the KVS is a capped KVS.
- Cnid: (CN id) A unique identifier for the KVS.
- CN name: Name of the KVS.
- Meta size: The Info record is followed by opaque metadata. This field records the size of this
  metadata. See the "Meta[]" field below.
- Meta[]: Opaque metadata ecoded/decoded by the caller.

### KVS_DELETE

- Cnid: (CN id) A unique identifier for the KVS.
- CN name: Name of the KVS.

### CNDB META

- Seqno max: Max seqno of the persisted records in the KVDB.

### TX_START

The number of create and delete records aren't recorded here. They can be tracked as they come
along. A txn is "complete" when the number of `TX_KVSET_CREATE` records and `ACK-C` records are equal. A
"complete" txn is one that can be rolled forward if necessary.

- TX id: A unique id for the CNDB txn. Note that a txn can span different cnids.
- Seqno: KVDB seqno at the time of logging this record.
- Ingest id: Every ingest operation gets a unique id. If `TX_START` does not describe an ingest operation,
  the value is set to `CNDB_INVAL_INGESTID`.
- Transaction horizon: Transaction horizon for an ingest. This is used by WAL to reclaim its files.
  When the operation is not an ingest, the value is set to `CNDB_INVAL_HORIZON`.

### TX_NODE

- TX id: Transaction id to tie this record to the corresponding `TX_START` record.
- Cnid: (CN id) A unique identifier for the KVS.
- Old node cnt: Number of nodes being deleted
- New node cnt: Number of nodes being created that will replace the old nodes.
Old Node Ids (packed u64 fields).
New Node Ids (packed u64 fields).

Node id 0 is reserved for the root node. There's no `txnode` record for the root node. A
root node always exists. `TX_KVSET_CREATE` records would use node id 0 when a kvset is created in the root node.

Only nodes at level 1 are logged explicitly in CNDB.

### TX_KVSET_CREATE

When a kvset is split, unless a kblock is rewritten, the vblock idx stored will not be sufficient to
fetch the value for a key. In addition to the vblock idx, a vgroup id is also stored in the kmd
region for the key's value. So the vblock idx acts as the index within a vgroup. After a split, in
the kvset that's moved to the other node, each vblock index in a vgroup is now offset by a the
number of vblocks that were moved to the other kvset. The `vgroup->offset` mapping in the
`TX_KVSET_CREATE` record handles this change.

During a kvset split, some mblocks are rewritten while others are just moved around. If the KVDB
crashes before the split completes, then recovery is required before the KVDB can be brought online.
This includes cleaning up the mblocks that were created for this split but not the mblocks that were
moved. The KMap and VMap bitmaps represent blocks that were created.
i.e. for a KMap/VMap entry:
  0: mblock was moved. Do not delete on rollback
  1: mblock was created. Delete on rollback.

- TX id: Transaction id to tie this record to the corresponding `TX_START` record.
- Cnid: (CN id) A unique identifier for the KVS.
- Tag: A unique number used to match with corresponding `ACK-C` records.
- Vgroup-Offset map cnt: Number of entries for `vgroup->offset` mapping
- Kblock cnt: Number of kblocks.
- Vblock cnt: Number of vblocks.
- KMap num bytes: Number of bytes that contain the KMap bitmap
- VMap num bytes: Number of bytes that contain the VMap bitmap
Vgroup-offset map
KMap bits (u8 fields)
VMap bits (u8 fields)
List of Kblock IDs (u64 fields)
List of Vblock IDs (u64 fields)

### TX_KVSET_META

There's a `TX_KVSET_META` record to go with every `TX_KVSET_CREATE` record. This record contains all
the metadata for the kvset described by the `TX_KVSET_CREATE` record.

- TX id: Transaction id to tie this record to the corresponding `TX_START` record.
- Cnid: (CN id) A unique identifier for the KVS.
- Tag: A unique number used to match with corresponding `ACK` records.
- Node id: Node id to which this kvset belongs. Node ids are found in `TX_NODE` records.
- Dgen: Data generation number. Everytime a new kvset is created during ingest, it gets a new dgen.
  Kvsets resulting from a compaction operation adopt the dgen of the src kvset with the largest dgen.
- Vused: Sum of lengths of referenced values across all vblocks.
- Compc: Number of times this kvset has undergone compactions.

### TX_KVSET_DELETE

- TX id: Transaction id to tie this record to the corresponding `TX_START` record.
- Cnid: (CN id) A unique identifier for the KVS.
- Tag: A unique number used to match with corresponding `ACK` records.
- Number of mblocks.
- List of Mblock IDs.

### ACK

All records until now are meant to log an intent. `ACK` and `NACK` commit and abort transactions (or
parts of transactions) repectively.

Types of `ACK` records (specified in the `ack_type` field of the `ACK` record) :
1. `ACK-C`: Ack a `TX_KVSET_CREATE` record. One `ACK` record for every `TX_KVSET_CREATE` record.
1. `ACK-D`: Ack a `TX_KVSET_DELETE` record. One `ACK` record for every `TX_KVSET_DELETE` record.

- TX id: Transaction id to tie this record to the corresponding `TX_START` record.
- Cnid: (CN id) A unique identifier for the KVS. Used only by Ack-D.
- Tag: Must match the `TX_KVSET_CREATE/TX_KVSET_DELETE` record that is being acknowledged.

### NACK

Mark txn as aborted.
- TX id: Transaction id to tie this record to the corresponding `TX_START` record.

## Operation

### New KVDB and KVS

- A new KVDB starts out with a CNDB that contains the version and a meta record.
- When a new KVS is created, an info record is appended to the CNDB. When the record type is set to
  `KVS_CREATE`.

### Tree shape changes

- On startup, CNDB will read through `TX_NODE` records in order and maintain a `master node list`.
- When a `TX_NODE` record is read, an entry is added to a pending node list. When this txn is
  committed, the `master node list` is updated with the node replacements.
- On mdc compaction, CNDB would write its `TX_NODE` record based on the `master node list`.
- Operations:
  - First root spill.
  - Split and Join.
  - CNDB compaction: Encapsulate the current tree shape in the compacted CNDB view.

## Sample logs

Part 1: Beginning.
```
# Create KVDB
version magic=[...] version=01 captgt=1234567890
meta seqno=01

# Create KVS
> info cnid=01 pfxlen=00 flags=0x0 name=kvs01 metasz 2176 ...

# Ingest - no deletes
> tx    txid=01 seqno=[...] ingest_id=[...] txhorizon=[...]
> txc   txid=01 cnid=01 tag=01 kbk.cnt=01 vblk.cnt=01 ...
> ack-C txid=01 cnid=01 tag=01

# First root spill. Creates a single node at level 1 - n01
> tx     txid=02 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txnode txid=02 cnid=01 old.cnt=0 new.cnt=1 node=n01 # Create one node at level 1
> txc    txid=02 cnid=01 tag=01 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=02 cnid=01 tag=01 node=n01 dgen [...] vused [...] compc [...]
> txd    txid=02 cnid=01 tag=02 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=02 cnid=01 tag=03 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=02 cnid=01 tag=04 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=02 cnid=01 tag=05 kblk.cnt=01 vblk.cnt=01 ...
> ack-C  txid=02 tag=01
> ack-D  txid=02
> ack-D  txid=02
> ack-D  txid=02
> ack-D  txid=02
```

Part 2: Splits
```
# Split node=n01
> tx     txid=03 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txnode txid=03 cnid=01 old.cnt=1 new.cnt=2 node=n01 node=n02 node=n03
> txc    txid=03 cnid=01 tag=01 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=03 cnid=01 tag=01 node=n02 dgen [...] vused [...] compc [...]
> txc    txid=03 cnid=01 tag=02 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=03 cnid=01 tag=02 node=n02 dgen [...] vused [...] compc [...]
> txc    txid=03 cnid=01 tag=03 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=03 cnid=01 tag=03 node=n03 dgen [...] vused [...] compc [...]
> txc    txid=03 cnid=01 tag=04 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=03 cnid=01 tag=04 node=n03 dgen [...] vused [...] compc [...]
> txd    txid=03 cnid=01 tag=05 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=03 cnid=01 tag=06 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=03 cnid=01 tag=07 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=03 cnid=01 tag=08 kblk.cnt=01 vblk.cnt=01 ...
> ack-C  txid=02 tag=01
> ack-C  txid=02 tag=02
> ack-C  txid=02 tag=03
> ack-C  txid=02 tag=04
> ack-D  txid=02 tag=05
> ack-D  txid=02 tag=06
> ack-D  txid=02 tag=07
> ack-D  txid=02 tag=08

# L1_nodelist: 0->n2->n3

# Split node=n02. Each node contains 2 kvsets.
> tx     txid=04 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txnode txid=04 cnid=01 old.cnt=1 new.cnt=2 node=n02 node=n04 node=n05
> txc    txid=04 cnid=01 tag=01 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=04 cnid=01 tag=01 node=n04 dgen [...] vused [...] compc [...]
> txc    txid=04 cnid=01 tag=02 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=04 cnid=01 tag=02 node=n04 dgen [...] vused [...] compc [...]
> txc    txid=04 cnid=01 tag=03 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=04 cnid=01 tag=03 node=n05 dgen [...] vused [...] compc [...]
> txc    txid=04 cnid=01 tag=04 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=04 cnid=01 tag=04 node=n05 dgen [...] vused [...] compc [...]
> txd    txid=04 cnid=01 tag=05 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=04 cnid=01 tag=06 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=04 cnid=01 tag=07 kblk.cnt=01 vblk.cnt=01 ...
> txd    txid=04 cnid=01 tag=08 kblk.cnt=01 vblk.cnt=01 ...
> ack-C  txid=04 tag=01
> ack-C  txid=04 tag=02
> ack-C  txid=04 tag=03
> ack-C  txid=04 tag=04
> ack-D  txid=04 tag=05
> ack-D  txid=04 tag=06
> ack-D  txid=04 tag=07
> ack-D  txid=04 tag=08

# L1_nodelist: 0->n4->n5->n3
```

Part 3: Join - No kvset/mblock delete required.
```
> tx     txid=05 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txnode txid=05 cnid=01 old.cnt=2 new.cnt=1 node=n04 node=n05 node=n06
> txc    txid=05 cnid=01 tag=01 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=05 cnid=01 tag=01 node=n06 dgen [...] vused [...] compc [...]
> txc    txid=05 cnid=01 tag=02 kblk.cnt=01 vblk.cnt=01 ...
> txm    txid=05 cnid=01 tag=02 node=n06 dgen [...] vused [...] compc [...]
> ack-C  txid=05 tag=01
> ack-C  txid=05 tag=02

# L1_nodelist: 0->n6->n3
```

Part 4: CNDB compaction (txm records are skippped for brevity)
```
# Create N nodes from 0 nodes. Encapsulates the tree shape.
> tx     txid=06 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txnode txid=06 cnid=01 old.cnt=0 new.cnt=2 node=n06 node=n3
> txc    txid=06 cnid=01 tag=01 ...
> txc    txid=06 cnid=01 tag=02 ...
> txc    txid=06 cnid=01 tag=03 ...
> ... more txc records. May contain ack-D records if this is rolling over CNDB on a live system.
> ack-C  txid=06 tag=01
> ack-C  txid=06 tag=02
> ack-C  txid=06 tag=03
> ... more ack-C records. One for each txc record.
```

### Incremental spills

Incremental spill refers to the fact that a spill constructs and creates the kvset of a child
node and adds it to the node list before proceeding to the next child node. A full spill operation
can take a while, but it doesn't have to hold up all split/join/kcompact/kvcompact operations until
it finishes. Only the child node to which the spill is writing data needs to be prevented from
participating in any maintenance operations.

To achieve this, CN logs each incremental step in spill as a separate transaction. Also, deleting the
source kvsets is its own transaction. If the process crashes in the middle of this spill, CN can
resume the spill operation where it left off.

Consider the following root spill (txm records are skipped for brevity):

```
# incremental spill step 1 of 3
> tx     txid=07 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txc    txid=07 cnid=01 tag=01 ...
> ack-C  txid=07 tag=01

# incremental spill step 2 of 3
> tx     txid=08 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txc    txid=08 cnid=01 tag=01 ...
> ack-C  txid=08 tag=01

# incremental spill step 3 of 3
> tx     txid=09 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txc    txid=09 cnid=01 tag=01 ...
> ack-C  txid=09 tag=01

# delete source kvsets
> tx     txid=10 seqno=[...] ingest_id=CNDB_INVAL_INGESTID txhorizon=CNDB_INVAL_HORIZON
> txd    txid=10 cnid=01 tag=01 ...
> txd    txid=10 cnid=01 tag=02 ...
> txd    txid=10 cnid=01 tag=03 ...
> ack-D  txid=10 tag=01
> ack-D  txid=10 tag=02
> ack-D  txid=10 tag=03
```

Consider the case where the above spill operation crashes right before the last `ACK-C` (step 3 of
3) is logged. When the KVDB is reopened, the tree will contain kvsets resulting from this spill in
the first two child nodes, but not the third one. Also, the three source kvsets in the root node
would be intact.
- The scheduler would see the kvsets in the root node and schedule a spill operation.
- Before building a kvset for a child, look at the kvsets in the child nodes and, based on the dgen
  range, determine whether this child already contains the spilled data. If yes, move to the next
  child node (by seeking to the node's edge key). If not, run through the merge loop and continue
  the spill.

This approach ensures that CNDB and the compaciton logic remain decoupled from each other.
