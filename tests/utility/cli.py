# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

import argparse
import atexit
import os
import pathlib
import shutil
import signal
import sys
import tempfile
from types import FrameType
from typing import Optional


def __default_dir() -> str:
    directory = tempfile.gettempdir()
    for d in [
        os.getenv("HSE_TEST_RUNNER_DIR"),
        os.getenv("MESON_BUILD_ROOT"),
    ]:
        if d:
            directory = d
            break

    tmpdir = tempfile.TemporaryDirectory(
        prefix=f"mtest-{pathlib.Path(sys.argv[0]).name}-", dir=directory
    )

    def __cleanup(sig: int, frame: Optional[FrameType]) -> None:
        shutil.rmtree(tmpdir.name)

    atexit.register(shutil.rmtree, tmpdir.name)
    for s in set(signal.Signals) - {signal.SIGKILL, signal.SIGSTOP, signal.SIGCHLD}:
        signal.signal(s, __cleanup)

    return tmpdir.name


__parser = argparse.ArgumentParser()
__parser.add_argument(
    "-C",
    "--home",
    type=pathlib.Path,
    default=__default_dir(),
    help="Path to KVDB home directory",
)
__parser.add_argument("-c", "--config", type=pathlib.Path, help="Path to config file")

__ns = __parser.parse_args()

HOME: pathlib.Path = __ns.home
CONFIG: pathlib.Path = __ns.config
