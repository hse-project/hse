#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

#doc: run omf_encoder_perf

. "$(dirname "${BASH_SOURCE[0]}")/smoke.subr"

cmd omf_encoder_perf
