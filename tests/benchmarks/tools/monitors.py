# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

import os
import subprocess

from tools import config
from tools.helpers import shlex_join


def _spawn(dest_dir, args, logname):
    logbase = os.path.join(dest_dir, logname)
    out = f"{logbase}.out"
    cmdline = f"{logbase}.cmdline"

    with open(cmdline, "w") as fd:
        fd.write(shlex_join(args))
        fd.write("\n")

    fd = open(out, "w")
    proc = subprocess.Popen(args, stdout=fd, stderr=subprocess.STDOUT)

    return proc, fd


def spawn_pidstat(dest_dir, pid):
    args = ["pidstat", "-r", "-u", "-h", "-p", str(pid), "1"]
    proc, fd = _spawn(dest_dir, args, "pidstat")
    return proc, fd


def spawn_vmstat(dest_dir):
    args = ["vmstat", "-t", "-w", "1"]
    proc, fd = _spawn(dest_dir, args, "vmstat")
    return proc, fd


def spawn_iostat(dest_dir):
    devices = config.MONITOR_DEVICES

    args = ["iostat", "-d", "-x", "-t"]
    args.extend(devices)
    args.append("1")

    proc, fd = _spawn(dest_dir, args, "iostat")
    return proc, fd
