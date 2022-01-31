/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

package cn

import (
	"container/list"
	"math"
)

type compactionStrategy int

const (
	K_COMPACT compactionStrategy = iota
	KV_COMPACT
)

type nodeLevel uint

const (
	ROOT nodeLevel = iota
	LEAF
)

type node struct {
	id       uint64
	level    nodeLevel
	dirty    bool
	children *list.List
	kvsets   *list.List
	kvsetIdx uint64

	tree *Tree

	stats nodeStats
}

type nodeState struct {
	ID     uint64   `json:"node-id"`
	Size   uint64   `json:"size"`
	KVSets []*kvSet `json:"kvsets"`
}

type nodeStats struct {
	ingests       uint
	spills        uint
	ingested      uint64
	written       uint64
	splits        uint
	kCompactions  uint
	kvCompactions uint
}

func (n *node) addKVSet(size uint64, compc uint, vgroups uint) {
	n.kvsets.PushFront(&kvSet{
		ID:           n.kvsetIdx,
		CompactCount: compc,
		Vgroups:      vgroups,
		Size:         size,
	})

	n.kvsetIdx++

	n.dirty = true
}

func (n *node) compact(mark *list.Element, runLength uint, strategy compactionStrategy) *kvSet {
	var size uint64

	/* We assume that all KVSets we are about to compact have the same
	 * compactCount.
	 */
	compactCount := mark.Value.(*kvSet).CompactCount + 1

	var vgroups uint

	if strategy == K_COMPACT {
		n.stats.kCompactions++
		vgroups = 0
	} else if strategy == KV_COMPACT {
		n.stats.kvCompactions++
		vgroups = 1
	} else {
		panic("Unimplemented compaction strategy")
	}

	for i := uint(0); i < runLength; i++ {
		// Save off the prev element before removing from the list
		safe := mark.Prev()

		k := n.kvsets.Remove(mark).(*kvSet)

		if strategy == K_COMPACT {
			vgroups += k.Vgroups
		}

		mark = safe

		size += k.Size
	}

	compacted := &kvSet{
		ID:           n.kvsetIdx,
		CompactCount: compactCount,
		Vgroups:      vgroups,
		Size:         size,
	}

	n.kvsetIdx++

	return compacted
}

func (n *node) ingest(data uint64) {
	n.stats.ingests++
	n.stats.ingested += data
	n.stats.written += data
	n.addKVSet(data, 0, 1)

	if err := emitIngestEvent(n.tree, n.stats.ingests, n.id, data); err != nil {
		panic(err)
	}
}

func (n *node) maintain() {
	if n.level == ROOT {
		if n.children.Len() == 0 {
			if n.size() < n.tree.params.RootNode.InitialSpillSize {
				return
			}

			// Create the two initial leaf nodes to spill into
			n.tree.addNode(n)
			n.tree.addNode(n)

			n.spill()

			return
		}

		if n.size() < n.tree.params.RootNode.SpillSize {
			return
		}

		n.spill()
	} else {
		var toCompact uint64
		var runLength uint
		var compc uint
		var mark *list.Element
		var vgroups uint

	KCOMPACT:
		if n.kvsets.Len() < int(n.tree.params.LeafNode.RunLengthMin) {
			goto SPLIT
		}

		toCompact = uint64(0)
		runLength = uint(0)
		compc = uint(math.MaxUint32)

		mark = n.kvsets.Back()

		for kvset := mark; kvset != nil; kvset = kvset.Prev() {
			if compc != kvset.Value.(*kvSet).CompactCount && runLength < n.tree.params.LeafNode.RunLengthMin {
				compc = kvset.Value.(*kvSet).CompactCount
				mark = kvset
				toCompact += kvset.Value.(*kvSet).Size
				runLength = 1
				continue
			} else if runLength >= n.tree.params.LeafNode.RunLengthMax-1 {
				// One last increment because Go doesn't support inline postfix or prefix
				runLength++
				break
			}

			runLength++
		}

		if runLength >= n.tree.params.LeafNode.RunLengthMin && mark.Value.(*kvSet).Vgroups <= n.tree.params.LeafNode.VgroupLimit {
			compacted := n.compact(mark, runLength, K_COMPACT)
			n.kvsets.PushFront(compacted)

			n.tree.root.stats.written += (toCompact * uint64(n.tree.params.KeyLength) / uint64(n.tree.params.ValueLength))

			if err := emitKCompactEvent(n.tree, n.id, mark.Value.(*kvSet).ID, runLength, compc); err != nil {
				panic(err)
			}

			/* If we compacted the KVSets, but number of KVSets in the node is >= to
			 * the RunLengthMin, try to k-compact again.
			 */
			if n.kvsets.Len() >= int(n.tree.params.LeafNode.RunLengthMin) {
				goto KCOMPACT
			}
		}

	KVCOMPACT:
		if n.kvsets.Len() < int(n.tree.params.LeafNode.RunLengthMin) {
			goto SPLIT
		}

		toCompact = uint64(0)
		runLength = uint(0)
		vgroups = uint(math.MaxUint32)
		mark = n.kvsets.Back()

		for kvset := mark; kvset != nil; kvset = kvset.Prev() {
			if vgroups != kvset.Value.(*kvSet).Vgroups && runLength < n.tree.params.LeafNode.RunLengthMin {
				vgroups = kvset.Value.(*kvSet).Vgroups
				mark = kvset
				toCompact += kvset.Value.(*kvSet).Size
				runLength = 1
				continue
			} else if runLength >= n.tree.params.LeafNode.RunLengthMax-1 {
				// One last increment because Go doesn't support inline postfix or prefix
				runLength++
				break
			}

			runLength++
		}

		if runLength >= n.tree.params.LeafNode.RunLengthMin && mark.Value.(*kvSet).Vgroups > n.tree.params.LeafNode.VgroupLimit {
			compacted := n.compact(mark, runLength, KV_COMPACT)
			n.kvsets.PushFront(compacted)

			n.tree.root.stats.written += toCompact

			if err := emitKVCompactEvent(n.tree, n.id, mark.Value.(*kvSet).ID, runLength, vgroups); err != nil {
				panic(err)
			}

			/* If we compacted the KVSets, but number of KVSets in the node is >= to
			 * the RunLengthMin, try to kv-compact again.
			 */
			if n.kvsets.Len() >= int(n.tree.params.LeafNode.RunLengthMin) {
				goto KVCOMPACT
			}
		}

	SPLIT:
		nodeSize := n.size()

		if (n.stats.splits == uint(0) && nodeSize >= n.tree.params.LeafNode.InitialSplitSize) || (nodeSize >= n.tree.params.LeafNode.SplitSize) {
			n.stats.splits++

			split := n.tree.splitNode(n.tree.root, n)

			if err := emitSplitEvent(n.tree, nodeSize, n.id, split.id); err != nil {
				panic(err)
			}
		}
	}
}

func (n *node) size() uint64 {
	var total uint64
	for kvset := n.kvsets.Front(); kvset != nil; kvset = kvset.Next() {
		total += kvset.Value.(*kvSet).Size
	}

	return total
}

func (n *node) spill() {
	size := n.size()

	n.stats.written += size

	nodes := make([]uint64, n.children.Len())

	kvsetSize := size / uint64(n.children.Len())

	i := 0
	for child := n.children.Front(); child != nil; child = child.Next() {
		node := child.Value.(*node)

		node.addKVSet(kvsetSize, 0, 1)
		nodes[i] = node.id

		i++
	}

	// At this point, all the data has spilled, so remove KVSets from root node
	for kvset := n.kvsets.Front(); kvset != nil; {
		safe := kvset.Next()
		n.kvsets.Remove(kvset)
		kvset = safe
	}

	n.stats.spills++

	if err := emitSpillEvent(n.tree, n.stats.spills, n.id, size, nodes); err != nil {
		panic(err)
	}
}

func (n *node) splitKVSet(parent *node, kvset *kvSet) {
	kvset.Size /= 2

	parent.addKVSet(kvset.Size, kvset.CompactCount, kvset.Vgroups)
}
