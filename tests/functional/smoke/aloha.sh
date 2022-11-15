#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: a "hello world" test

. common.subr

trap cleanup EXIT

cmd echo aloha
cmd -i echo --not-an-option
