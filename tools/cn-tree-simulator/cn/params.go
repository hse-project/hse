/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

package cn

type TreeParams struct {
	Verbose     bool
	PrintState  bool
	KeyLength   uint
	ValueLength uint

	RootNode RootNodeParams
	LeafNode LeafNodeParams
}

type RootNodeParams struct {
	SpillSize        uint64
	InitialSpillSize uint64
}

type LeafNodeParams struct {
	SplitSize        uint64
	InitialSplitSize uint64
	VgroupLimit      uint
	RunLengthMin     uint
	RunLengthMax     uint
}
