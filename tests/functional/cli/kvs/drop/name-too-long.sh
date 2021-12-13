#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

. common.subr

# A KVS name must fit within a char[32] including the NUL byte
cmd -e hse kvs drop "$home" "$(python3 -c "print('a' * 32))")"
