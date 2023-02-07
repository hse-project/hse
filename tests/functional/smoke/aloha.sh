#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: a "hello world" test

. common.subr

trap cleanup EXIT

cmd echo aloha
cmd -i echo --not-an-option
