#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021-2022 Micron Technology, Inc. All rights reserved.

#doc: run omf_encoder_perf

. common.subr

trap cleanup EXIT

cmd omf_encoder_perf
