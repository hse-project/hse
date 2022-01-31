/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

package cn

import (
	"container/list"
)

type Tree struct {
	params  *TreeParams
	nodeIdx uint64

	root *node
}

type treeStats struct {
	Size          uint64       `json:"size"`
	KCompactions  uint         `json:"k-compactions"`
	KVCompactions uint         `json:"kv-compactions"`
	WriteAmp      float64      `json:"write-amp"`
	Root          *nodeStats   `json:"root,omitempty"`
	Leaves        []*nodeStats `json:"leaves,omitempty"`
}

type treeState struct {
	Root   nodeState   `json:"root"`
	Leaves []nodeState `json:"leaves"`
}

func (t *Tree) Ingest(data uint64) {
	for dirty := true; dirty; {
		dirty = false

		// Breadth-first walk of tree
		queue := list.New()
		queue.PushBack(t.root)

		n := queue.Remove(queue.Front())
		for n != nil {
			if n.(*node).dirty {
				n.(*node).maintain()
			}

			if n.(*node).children != nil {
				queue.PushBackList(n.(*node).children)
			}

			front := queue.Front()
			if front == nil {
				n = nil
			} else {
				n = queue.Remove(front)
			}
		}
	}

	t.root.ingest(data)
}

func NewTree(params *TreeParams) *Tree {
	tree := Tree{
		params: params,
		root: &node{
			id:       0,
			level:    ROOT,
			children: list.New(),
			kvsets:   list.New(),
		},
	}

	tree.nodeIdx++

	tree.root.tree = &tree

	return &tree
}

func (t *Tree) addNode(parent *node) {
	parent.children.PushFront(&node{
		id:     t.nodeIdx,
		level:  LEAF,
		tree:   t,
		kvsets: list.New(),
	})

	t.nodeIdx++
}

func (t *Tree) kCompactions() uint {
	var total uint

	for child := t.root.children.Front(); child != nil; child = child.Next() {
		total += child.Value.(*node).stats.kCompactions
	}

	return total
}

func (t *Tree) kvCompactions() uint {
	var total uint

	for child := t.root.children.Front(); child != nil; child = child.Next() {
		total += child.Value.(*node).stats.kvCompactions
	}

	return total
}

func (t *Tree) size() uint64 {
	total := t.root.size()

	for child := t.root.children.Front(); child != nil; child = child.Next() {
		for kvset := child.Value.(*node).kvsets.Front(); kvset != nil; kvset = kvset.Next() {
			total += kvset.Value.(*kvSet).Size
		}
	}

	return total
}

func (t *Tree) splitNode(parent *node, src *node) *node {
	n := &node{
		id:     t.nodeIdx,
		level:  LEAF,
		tree:   t,
		kvsets: list.New(),
	}

	for kvset := src.kvsets.Back(); kvset != nil; kvset = kvset.Prev() {
		src.splitKVSet(n, kvset.Value.(*kvSet))
	}

	for child := parent.children.Front(); child != nil; child = child.Next() {
		if child.Value == src {
			parent.children.InsertBefore(n, child)
			break
		}
	}

	t.nodeIdx++

	return n
}

func (t *Tree) state() *treeState {
	rootKVSets := make([]*kvSet, t.root.kvsets.Len())

	var i, j uint
	for kvset := t.root.kvsets.Front(); kvset != nil; kvset = kvset.Next() {
		rootKVSets[i] = kvset.Value.(*kvSet)

		i++
	}

	leaves := make([]nodeState, t.root.children.Len())

	i = 0
	for child := t.root.children.Front(); child != nil; child = child.Next() {
		n := child.Value.(*node)

		leafKVSets := make([]*kvSet, n.kvsets.Len())

		j = 0
		for kvset := n.kvsets.Front(); kvset != nil; kvset = kvset.Next() {
			leafKVSets[j] = kvset.Value.(*kvSet)

			j++
		}

		leaves[i] = nodeState{
			ID:     n.id,
			Size:   n.size(),
			KVSets: leafKVSets,
		}

		i++
	}

	return &treeState{
		Root: nodeState{
			Size:   t.root.size(),
			KVSets: rootKVSets,
		},
		Leaves: leaves,
	}
}

func (t *Tree) stats() *treeStats {
	var rootStats *nodeStats
	var leafStats []*nodeStats
	if t.params.Verbose {
		rootStats = &t.root.stats

		leafStats = make([]*nodeStats, t.root.children.Len())

		i := 0
		for child := t.root.children.Front(); child != nil; child = child.Next() {
			leafStats[i] = &child.Value.(*node).stats

			i++
		}
	}

	return &treeStats{
		Size:          t.size(),
		KCompactions:  t.kCompactions(),
		KVCompactions: t.kvCompactions(),
		WriteAmp:      float64(t.root.stats.written) / float64(t.root.stats.ingested),
		Root:          rootStats,
		Leaves:        leafStats,
	}
}
