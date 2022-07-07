#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2020-2022 Micron Technology, Inc. All rights reserved.

import argparse
import subprocess as sp
import yaml
import sys
import time
import json
import pathlib
import signal
from typing import Any, Dict, OrderedDict, Optional

desc = (
    "print cn tree shape\n\n"
    "example1: %(prog)s --home /var/lib/hse kvs1 -r3\n"
    "example2: cat file.yml | %(prog)s"
)
PARSER = argparse.ArgumentParser(
    description=desc, formatter_class=argparse.RawTextHelpFormatter
)
PARSER.add_argument(
    "-r",
    "--refresh",
    type=int,
    metavar="N",
    help="refresh every N secs",
    required=False,
)

PARSER.add_argument("-k", "--nokvsets", help="do not show kvsets", action="store_true")
PARSER.add_argument("-y", "--yaml", help="output in yaml", action="store_true")

PARSER.add_argument(
    "-C",
    "--home",
    help="Home directory",
    type=pathlib.Path,
    default=pathlib.Path.cwd(),
)
PARSER.add_argument("kvs", help="kvs name")

def full_tree(ybuf: Optional[OrderedDict[str, Any]], opt):
    if not ybuf or "info" not in ybuf:
        return

    # Vector of initial column widths (i.e., compc, dgen, keys, ...)
    #
    widthv = [ 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 1 ]

    print("t -,-    -     -   ", end=""),

    col = 1
    for key, val in ybuf["info"].items():
        n = len(str(val)) + 1
        if n > widthv[col]:
            widthv[col] = n
        width = widthv[col]
        col += 1
        print(f"{key} {val:<{width}} ", end="")
    print()
    print()

    if ybuf["info"]["open"] == False:
        return

    # Print info for each node in the kvs.
    #
    for node in ybuf["nodes"]:
        if node["info"]["dgen"] == 0:
            continue

        loc = node["loc"]
        print(f"n {loc['level']},{loc['offset']}    -     -   ", end="")

        col = 1
        for key, val in node["info"].items():
            width = widthv[col]
            col += 1
            print(f"{key} {val:<{width}} ", end="")
        print()

        if opt.nokvsets:
            continue

        if node["info"]["kvsets"] == 0:
            print()
            continue

        # Print info for each kvset in the current node.
        #
        for kvset in node["kvsets"]:
            index = kvset.pop("index")
            print(f"k {loc['level']},{loc['offset']},{index:<2} ", end="")

            col = 0;
            for key, val in kvset.items():
                width = widthv[col]
                col += 1
                print(f"{key} {val:<{width}} ", end="")
            print()
        print()


def process_stdin() -> int:
    if sys.stdin.isatty():
        print("Not a TTY", file=sys.stderr)
        return -1

    buf = sys.stdin.read()
    if not buf:
        return -1

    ybuf = yaml.safe_load(buf)
    full_tree(ybuf)
    return 0


def main() -> int:
    if len(sys.argv) == 1:
        return process_stdin()

    opt = PARSER.parse_args()

    with open(opt.home / "kvdb.pid", "r") as pfh:
        content = json.load(pfh)
        sock: str = content["socket"]["path"]

    if opt.refresh:
        sp.call("clear")
        pass

    # [HSE_REVISIT] We need a way to map opt.home to kvdb alias.
    # For now we implement a crude scan, which will likely fail
    # miserably if there is more than one active kvdb that have
    # identical kvs names.
    #
    kvdbalias = 0

    while True:
        url = f"http://localhost/kvdb/{kvdbalias}/kvs/{opt.kvs}/cn/tree"

        try:
            buf = sp.check_output(
                [
                    "curl",
                    "--silent",
                    "--fail",
                    "--noproxy",
                    "localhost",
                    "--unix-socket",
                    sock,
                    url,
                ]
            )
        except sp.CalledProcessError:
            if kvdbalias < 9:
                kvdbalias = kvdbalias + 1
                continue
            return -1

        if opt.yaml:
            print(buf)
        else:
            ybuf = yaml.safe_load(buf)
            full_tree(ybuf, opt)

        if not opt.refresh:
            return 0

        time.sleep(opt.refresh)
        sp.call("clear")


if __name__ == "__main__":
    try:
        rc = main()
        sys.exit(rc)
    except KeyboardInterrupt:
        sys.exit(128 + signal.SIGINT)
