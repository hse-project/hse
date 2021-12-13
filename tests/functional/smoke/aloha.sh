#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: a "hello world" test

. common.subr

cmd echo aloha
cmd -i echo --not-an-option
