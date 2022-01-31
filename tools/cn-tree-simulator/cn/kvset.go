/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2022 Micron Technology, Inc. All rights reserved.
 */

package cn

type kvSet struct {
	ID           uint64 `json:"id"`
	CompactCount uint   `json:"compc"`
	Vgroups      uint   `json:"vgroups"`
	Size         uint64 `json:"size"`
}
