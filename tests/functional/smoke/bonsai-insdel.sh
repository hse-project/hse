#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: stress test bonsai tree insert/delete

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

# simple 30 second, test one bonsai tree, three threads
cmd bnt -j3 -t30 -okvtreec=1 -i128k -v

# stressful 60 second test, many bonsai trees, twice as many threads as trees
cmd bnt -t60 -v
