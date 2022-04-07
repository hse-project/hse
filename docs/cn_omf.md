# OMF descriptions

## KBlocks (Key Blocks)

KBlocks are mblocks that hold keys in sorted order. See cn/omf.h for the
structures associated with the various omf components. All the on-media elements
are stored in little endian ordering.

    +--------+--------+--------+-------------+
    |        |        |        |             |
    | Kblock | WBTree | Bloom  | HyperLogLog |
    | Header |        | Filter |             |
    |        |        |        |             |
    +--------+--------+--------+-------------+

### Kblock Header

The kblock header contains information about where the other components of the
kblock are located and some other metadata. It also stores the smallest and
largest keys in the kblock as well as the smallest and largest sequence numbers.

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
    1. `vtype_val`:   Normal value. This stores an offset to the actual value located in the vblock.
    2. `vtype_ival`:  Small value. Value length is no greater than 8 bytes.
    3. `vtype_zval`:  Zero-length value
    4. `vtype_tomb`:  Tombstone
    5. `vtype_ptomb`: Prefix tombstone

    +--------------------+
    | count              |
    +--------------------+
    | vtype              | vtype_val
    | sequence number    |
    | vgroup ID          |
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

The `vblock index` stored in kmd is an index within the vgroup specified by `vgroup ID`.

### PTree (A WBTree that holds prefix tombstones)

This portion has the same format as the main WBTree.  A PTree can exist only in the last kblock of a kvset.

### Bloom Filter

#### Bloom Header

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

## Vblocks (Value Blocks)

VBlocks consist of values followed by a trailer. The offset of a specific value
and its length are obtained from the kmd entry for this value which is linked to
the corresponding key.

### Vblock Trailer

Placed at the end of vblock - 4K bytes.

    +---------------------+
    | u32 vbh_magic       |
    | u32 vbh_version     |
    | u32 vbh_min_key_off | Offset of the min key
    | u32 vbh_min_key_len | Length of the min key
    | u32 vbh_max_key_off | Offset of the max key
    | u32 vbh_max_key_len | Length of the max key
    |---------------------|
    | min_key             | 1344 bytes is reserved at all times
    |---------------------|
    | max_key             | 1344 bytes is reserved at all times
    +---------------------+

## Hblocks (Header blocks)

    +----------+--------+-------------+-------+
    |          |        |             |       |
    | Metadata | Vblock | HyperLogLog | PTree |
    |  Header  | Index  |             |       |
    |          | Adjust |             |       |
    +----------+--------+-------------+-------+

### Hblock Header

    +---------------------------+
    | u32 hbh_magic             |
    | u32 hbh_version           |
    | u32 hbh_num_kblocks       | Number of kblocks within the kvset
    | u32 hbh_num_vblocks       | Number of vblocks within the kvset
    | u32 hbh_num_vgroups       | Number of vgroups within the kvset
    | u8  hbh_kblk_trim_type    | Enum representing no trim, start trim, or end trim
    | u16 hbh_kblk_trim_pg      | WBTree leaf node of trim key
    | u16 hbh_kblk_trim_off     | Trim key offset within node
    | u32 hbh_hlog_off_pg       | Offset of the hlog
    | u32 hbh_hlog_len_pg       | Length of the hlog (constant 20K)
    | u32 hbh_ptree_hdr_off     | Offset of the ptree header
    | u32 hbh_ptree_hdr_len     | Length of the ptree header
    | u32 hbh_ptree_data_off_pg | Offset of the ptree data
    | u32 hbh_ptree_data_len_pg | Offset of the ptree data
    | u32 hbh_vblk_idx_adj_off  | Offset of the vblock index adjust
    | u32 hbh_vblk_idx_adj_len  | Length of the vblock index adjust
    +---------------------------+

### Kblock Trim

Kblock trim masks parts of a kblock's data. During a kvset split, a portion of
a kblock will be hidden. Each segment is the trim associated with 1 kblock. The
range represented is inclusive. The only kblocks that can have trim are the
first or last kblock within a kvset. The first kblock will trim from page 0,
offset 0 to `hbh_kblk_trim_pg`, `hbh_kblk_trim_off`. The last kblock will trim
from `hbh_kblk_trim_pg`, `hbh_kblk_trim_off` to the last page, last key.

### Vblock Index Adjust

The index indicates that from the previous index + 1 to the current index, all
index adjustments must be subtracted by the accompanying adjustment value.

    +-------------------+
    | ...               |
    +-------------------+
    | u32 vbia_vblk_idx | Barrier vblock index
    | u32 vbia_adj      | Adjustment value
    +-------------------+
    | ...               |
    +-------------------+

### HyperLogLog

Composite hlog of the entire keyspace contained within the kvset.

### PTree

This portion has the same format as a regular WBTree. This stores prefix
tombstone data rather than key data however.

## Examples

### Kvset Split

Given a key to split on, we have to find the kblock to mask and the vblocks
to split.

Given two destination kvsets, left and right, add all kblocks which are less
than the split key and completely contained within the new range of the left
kvset to said kvset. When the kblock containing the split key has been iterated
to, we need to add it to both the left and the right kvset, but it will have a
different mask depending on which kvset you are looking at.

On the left kvset, set `hbh_kblk_trim_type` to `KBLOCK_TRIM_START`. In the event
the split key is the end of a WBTree leaf node, set `hbh_kblk_trim_pg` to the
next WBTree leaf node index, and set `hbh_kblk_trim_off` to `0`. Otherwise, set
`hbh_kblk_trim_pg` to the WBTree lead node index that includes the split key,
and set `hbh_kblk_trim_off` to the offset of the split key `+ 1`.

On the right kvset, set `hbh_kblk_trim_type` to `KBLOCK_TRIM_END`, set
`hbh_kblk_trim_pg` to the WBTree leaf node index containing the split key, and
set `hbh_kblk_trim_off` to the offset of the split key within
`hbh_kblk_trim_pg`.

From this point, we can iterate over the rest of the kblocks while adding them
to the right kvset.

Onto the vblocks. Iterate over all the vblocks. When the keyspace containing
the vblock fits within either the left or the right kvset, add it to the
determined kvset. In the event a vblock's keyspace spans across the split key,
make a copy of the vblock for one of the kvsets and move the original vblock
into the other. Keep track of the vblock indexes for vblocks that span the split
key.

Once you have collected all the vblock indices, we can construct the
[vblock index adjust](#vblock-index-adjust). Say we have vblock indicies 0-4.
Vblock 2 must be split becauses its keyspace runs through the split key. Let's
say vblocks 0 and 1 belong to the left kvset while 3 and 4 belong to the right
kvset. The vblock index adjust for the left and right kvsets will look like the
following:

__LEFT__: (2, 0)

All indices less than or equal to 2 must be subtracted by 0 to get the new
vblock index in the left kvset.

__RIGHT__: (4, 2)

All indices less than or equal to 4 must be subtracted by 2 to get the new
vblock index in the right kvset.

The vblock index adjust is most useful when getting the vblock index out of a
KMD entry.
