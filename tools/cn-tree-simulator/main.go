/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/hse-project/hse/tools/cn-tree-simulator/cn"
)

type SimulationParams struct {
	finalTreeSize uint64
	ingestSize    uint64

	cn cn.TreeParams
}

var params SimulationParams

func startSimulation() {
	cnTree := cn.NewTree(&params.cn)

	ingests := uint((params.finalTreeSize) / params.ingestSize)

	for i := uint(0); i < ingests; i++ {
		cnTree.Ingest(params.ingestSize)
	}
}

func main() {
	fs := flag.NewFlagSet("cn-tree-simulator", flag.ExitOnError)

	fs.Uint64Var(&params.finalTreeSize, "final-tree-size", 2<<40, "Final tree size")
	fs.Uint64Var(&params.ingestSize, "ingest-size", 2<<30, "Ingest size")
	fs.BoolVar(&params.cn.PrintState, "print-state", false, "Print tree state alongside every event")
	fs.BoolVar(&params.cn.Verbose, "verbose", false, "Print stats for every node")
	fs.UintVar(&params.cn.KeyLength, "key-length", 1000, "Key length")
	fs.UintVar(&params.cn.ValueLength, "value-length", 7000, "Value length")
	fs.Uint64Var(&params.cn.RootNode.SpillSize, "spill-size", 8<<30, "Spill size")
	fs.Uint64Var(&params.cn.RootNode.InitialSpillSize, "initial-spill-size", 8<<30, "Initial spill size")
	fs.Uint64Var(&params.cn.LeafNode.SplitSize, "split-size", 8<<30, "Split size")
	fs.Uint64Var(&params.cn.LeafNode.InitialSplitSize, "initial-split-size", 8<<30, "Initial split size")
	fs.UintVar(&params.cn.LeafNode.VgroupLimit, "vgroup-limit", 4, "Number of vgroups allowed to accumulate")
	fs.UintVar(&params.cn.LeafNode.RunLengthMin, "run-length-min", 4, "Minimum run length")
	fs.UintVar(&params.cn.LeafNode.RunLengthMax, "run-length-max", 4, "Maximum run length")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to parse command line arguments")
		os.Exit(1)
	}

	startSimulation()
}
