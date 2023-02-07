# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

from pathlib import Path

from tools.kmt import KmtTest


name = Path(__file__).stem
args = "-S0 -b -w0 -l1000 -i2000000 -t300"

t = KmtTest(name, args.split())

t.execute()
