# OMF descriptions

## KBlocks (Key blocks)

KBlocks are mblocks that hold keys in sorted order. See cn/omf.h for the structures associated with the various omf components. All the on-media elements are stored in little endian ordering.

    +--------+--------+-------+--------+----------+
    |        |        |       |        |          |
    | KBlock | WBTree | PTree | Bloom  | Hyperlog |
    | Header |        |       | Filter |          |
    |        |        |       |        |          |
    +--------+--------+-------+--------+----------+

### KBlock header

The kblock header contains information about where the other components of the kblock are located and some other metadata. It also stores the smallest and largest keys in the kblock as well as the smallest and largest sequence numbers.

note: max keylen == 1350 bytes

    +----------------------+ -- 0 bytes
    | u32 kbh_magic        |
    | u32 kbh_version      |
    | u32 kbh_hlog_doff_pg |
    | u32 kbh_hlog_dlen_pg |
    | u32 kbh_entries      |
    | u32 kbh_tombs        |
    | u32 kbh_key_bytes    |
    | u32 kbh_val_bytes    |
    | u32 kbh_min_koff     |
    | u32 kbh_min_klen     |
    | u32 kbh_max_koff     |
    | u32 kbh_max_klen     |
    | u32 kbh_wbt_hoff     |
    | u32 kbh_wbt_hlen     |
    | u32 kbh_wbt_doff_pg  |
    | u32 kbh_wbt_dlen_pg  |
    | u32 kbh_blm_hoff     |
    | u32 kbh_blm_hlen     |
    | u32 kbh_blm_doff_pg  |
    | u32 kbh_blm_dlen_pg  |
    | u32 kbh_pt_hoff      |
    | u32 kbh_pt_hlen      |
    | u32 kbh_pt_doff_pg   |
    | u32 kbh_pt_dlen_pg   |
    | u64 kbh_min_seqno    |
    | u64 kbh_max_seqno    |
    | ...                  |
    |----------------------| -- 1369 bytes (4096 - 1350 - 1350)
    | max_key              |
    | (replicated here)    |
    |----------------------| -- 2746 bytes (4096 - 1350)
    | min_key              |
    | (replicated here)    |
    +----------------------+ -- 4096 bytes

### Wanna B-Tree (WBTree)

The WBTree consists of the header, leaf nodes and internal nodes.  The last internal node is the root node. Each node is one 4K byte page.

    +--------+--------+----------+-------+
    |        |        |          |       |
    | WBTree | Leaf   | Internal | Root  |
    | Header | Nodes  | Nodes    | Node  |
    |        |        |          |       |
    +--------+--------+----------+-------+

WBTree Header

    +----------------------+
    | u32 wbt_magic        |
    | u32 wbt_version      |
    | u16 wbt_root         |
    | u16 wbt_leaf         |
    | u16 wbt_leaf_cnt     |
    | u16 wbt_kmd_pgc      |
    | u32 wbt_reserved1    |
    | u32 wbt_reserved2    |
    +----------------------+

WBTree Leaf Node (one 4K page):

    +--------------------+ Leaf Node Header:
    | u16 wbn_magic      |   integrity check
    | u16 wbn_num_keys   |   #entries in this node
    | u32 wbn_kmd        |   offset in kmd region to this node's kmd
    | u16 wbn_pfx_len    |   length of the longest common prefix
    | u16 wbn_padding    |   unused
    |--------------------| Longest common prefix
    | Longest common     |
    | prefix             |
    |--------------------| Entry for 1st key:
    | u16 lfe_koff       |   #bytes into this node
    | u16 lfe_kmd        |   kmd offset. If kmd_off == U16_MAX, actual kmd
    |                    |   offset is a 32bit value at key_off
    |--------------------|
    | ...                |
    |--------------------| Entry for last key
    | u16 lfe_koff       |
    | u16 lfe_kmd        |
    |--------------------|
    |--------------------|
    | Last key           |
    |--------------------|
    | ...                |
    |--------------------|
    | First key          |
    +--------------------+

WBTree Interior Node (one 4K page):

    +--------------------+ Internal Node Header:
    | u16 wbn_magic      |   integrity check
    | u16 wbn_num_keys   |   #entries in this node
    | u32 wbn_kmd        |   offset in kmd region to this node's kmd
    | u16 wbn_pfx_len    |   length of the longest common prefix
    | u16 wbn_padding    |   unused
    |--------------------| Longest common prefix
    | Longest common     |
    | prefix             |
    |--------------------| Entry for 1st internal node entry (ine):
    | u16 ine_koff       |   #bytes into this node
    | u16 ine_left_child |   left child pointer of this ine
    |--------------------|
    | ...                |
    |--------------------| Entry for (last-1) key
    | u16 ine_koff       |
    | u16 ine_left_child |
    |--------------------| Entry for last key
    | u16 ine_koff       |
    | u16 ine_left_child |   right child pointer
    |--------------------|
    |--------------------|
    | Last key           |
    |--------------------|
    | ...                |
    |--------------------|
    | First key          |
    +--------------------+

### KMD

    +----------+
    | count    | hg32_1024m 1-4 bytes, #KMD entries that follow
    +----------+
    | kmd[0]   |
    +----------+
    | kmd[1]   |
    +----------+
    | kmd[2]   |
    +----------+

  Each kmd entry stores information regarding a value: sequence number and a pointer to the value (or if the value is small, the value itself).
  Each kmd entry can describe one of the following 5 value types:
    1. `vtype_val`:   Normal value. This stores a pointer to the actual value located in the vblock.
    2. `vtype_ival`:  Small value. Value length is no greater than 8 bytes.
    3. `vtype_zval`:  Zero-length value
    4. `vtype_tomb`:  Tombstone
    5. `vtype_ptomb`: Prefix tombstone

    +--------------------+
    | count              |
    +--------------------+
    | vtype              | vtype_val
    | sequence number    |
    | vgroup id          |
    | vblock index       |
    | vblock offset      |
    | value length       |
    +--------------------+
    | vtype              | vtype_ival
    | sequence number    |
    | value length       |
    | value bytes        |
    +--------------------+
    | vtype              | vtype_zval / vtype_tomb / vtype_ptomb
    | sequence number    |
    +--------------------+

The `vblock idx` stored in kmd is an index within the vgroup specified by `vgroup id`.

### PTree (A WBTree that holds prefix tombstones)

This portion has the same format as the main WBTree.  A PTree can exist only in the last kblock of a kvset.

### Bloom filter

Bloom Header

    +-------------------+
    | u32 bh_magic      |
    | u32 bh_version    |
    | u32 bh_bitmapsz   |
    | u32 bh_modulus    |
    | u32 bh_bktshift   |
    | u16 bh_rsvd1      | Reserved
    | u8  bh_rotl       |
    | u8  bh_n_hashes   |
    | u32 bh_rsvd2      | Reserved
    | u32 bh_rsvd3      | Reserved
    +-------------------+

This is followed by the bloom filter.

### HyperLogLog

This region does not have a separate header, just the hyperloglog (hlog) bytes.  The offset and length in the KBlock header points to this region.  Each kblock stores its hlog bytes and the kvset's hlog can be composed using the individual kblock hlogs.

## VBlocks (Value blocks)

VBlocks consist of a header followed by all the values.  The offset of a specifc value and its length are obtained from the kmd entry for this value which is linked to the corresponding key.

### VBlock header

    +-------------------+
    | u32 vbh_magic     |
    | u32 vbh_version   |
    | u64 vbh_vgroup    |
    +-------------------+
