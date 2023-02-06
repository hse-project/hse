#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

#doc: run omf_encoder_perf

. common.subr

trap cleanup EXIT

cmd omf_encoder_perf
