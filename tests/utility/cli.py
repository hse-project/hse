# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2021 Micron Technology, Inc. All rights reserved.

import argparse
import pathlib

__parser = argparse.ArgumentParser()
__parser.add_argument(
    "-C",
    "--home",
    type=pathlib.Path,
    default=pathlib.Path.cwd(),
    help="Path to KVDB home directory",
)
__parser.add_argument("-c", "--config", type=pathlib.Path, help="Path to config file")

__ns = __parser.parse_args()

HOME: pathlib.Path = __ns.home
CONFIG: pathlib.Path = __ns.config
