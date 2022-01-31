/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

package cn

import (
	"encoding/json"
	"fmt"
)

type eventType string

const (
	INGEST_EVENT    eventType = "ingest"
	SPILL_EVENT     eventType = "spill"
	SPLIT_EVENT     eventType = "split"
	KCOMPACT_EVENT  eventType = "k-compact"
	KVCOMPACT_EVENT eventType = "kv-compact"
)

type event struct {
	Type  eventType  `json:"type"`
	Stats *treeStats `json:"stats"`
	State *treeState `json:"state,omitempty"`
}

type ingestEvent struct {
	event
	IngestID uint   `json:"ingest-id"`
	NodeID   uint64 `json:"node-id"`
	Size     uint64 `json:"size"`
}

type spillEvent struct {
	event
	SpillID uint     `json:"spill-id"`
	NodeID  uint64   `json:"node-id"`
	Size    uint64   `json:"size"`
	Nodes   []uint64 `json:"nodes"`
}

type splitEvent struct {
	event
	Size uint64 `json:"size"`
	Src  uint64 `json:"src-node-id"`
	Dest uint64 `json:"dest-node-id"`
}

type kCompactEvent struct {
	event
	NodeID    uint64 `json:"node-id"`
	StartID   uint64 `json:"start-id"`
	RunLength uint   `json:"run-length"`
	Compc     uint   `json:"compc"`
}

type kvCompactEvent struct {
	event
	NodeID    uint64 `json:"node-id"`
	StartID   uint64 `json:"start-id"`
	RunLength uint   `json:"run-length"`
	Vgroups   uint   `json:"vgroups"`
}

func emitIngestEvent(tree *Tree, id uint, nodeID uint64, size uint64) error {
	var state *treeState
	if tree.params.PrintState {
		state = tree.state()
	}

	event := ingestEvent{
		event: event{
			Type:  INGEST_EVENT,
			Stats: tree.stats(),
			State: state,
		},
		IngestID: id,
		NodeID:   nodeID,
		Size:     size,
	}

	output, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}

func emitSpillEvent(tree *Tree, id uint, nodeID uint64, size uint64, nodes []uint64) error {
	var state *treeState
	if tree.params.PrintState {
		state = tree.state()
	}

	event := spillEvent{
		event: event{
			Type:  SPILL_EVENT,
			Stats: tree.stats(),
			State: state,
		},
		SpillID: id,
		NodeID:  nodeID,
		Size:    size,
		Nodes:   nodes,
	}

	output, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}

func emitSplitEvent(tree *Tree, size uint64, src uint64, dest uint64) error {
	var state *treeState
	if tree.params.PrintState {
		state = tree.state()
	}

	event := splitEvent{
		event: event{
			Type:  SPLIT_EVENT,
			Stats: tree.stats(),
			State: state,
		},
		Src:  src,
		Dest: dest,
		Size: size,
	}

	output, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}

func emitKCompactEvent(tree *Tree, nodeID uint64, startID uint64, runLength uint, compc uint) error {
	var state *treeState
	if tree.params.PrintState {
		state = tree.state()
	}

	event := kCompactEvent{
		event: event{
			Type:  KCOMPACT_EVENT,
			Stats: tree.stats(),
			State: state,
		},
		NodeID:    nodeID,
		StartID:   startID,
		RunLength: runLength,
		Compc:     compc,
	}

	output, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}

func emitKVCompactEvent(tree *Tree, nodeID uint64, startID uint64, runLength uint, vgroups uint) error {
	var state *treeState
	if tree.params.PrintState {
		state = tree.state()
	}

	event := kvCompactEvent{
		event: event{
			Type:  KVCOMPACT_EVENT,
			Stats: tree.stats(),
			State: state,
		},
		NodeID:    nodeID,
		StartID:   startID,
		RunLength: runLength,
		Vgroups:   vgroups,
	}

	output, err := json.Marshal(event)
	if err != nil {
		return err
	}

	fmt.Println(string(output))

	return nil
}
