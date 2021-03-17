import os
import shlex
import subprocess

from tools import config


def _spawn(args, logname):
    logbase = os.path.join(config.LOG_DIR, logname)
    out = f"{logbase}.out"
    cmdline = f"{logbase}.cmdline"

    with open(cmdline, "w") as fd:
        fd.write(shlex.join(args))
        fd.write("\n")

    fd = open(out, "w")
    proc = subprocess.Popen(args, stdout=fd, stderr=subprocess.STDOUT)

    return proc, fd


def spawn_pidstat(pid):
    args = ["pidstat", "-r", "-u", "-h", "-p", str(pid), "1"]
    proc, fd = _spawn(args, "pidstat")
    return proc, fd


def spawn_vmstat():
    args = ["vmstat", "-t", "-w", "1"]
    proc, fd = _spawn(args, "vmstat")
    return proc, fd


def spawn_iostat():
    devices = config.MONITOR_DEVICES

    args = ["iostat", "-d", "-x", "-t", "-N"]
    args.extend(devices)
    args.append("1")

    proc, fd = _spawn(args, "iostat")
    return proc, fd
