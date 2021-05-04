#!/usr/bin/env python3

import argparse
import subprocess as sp
import yaml
import sys
import time
import os
from typing import Any, Dict, Optional


def full_tree(ybuf: Optional[Dict[str, Any]]):
    if not ybuf or "info" not in ybuf:
        return

    print("t ", end=""),
    oids = ["oid1", "oid2"]

    for key, val in ybuf["info"].items():
        print(f"{key} {val} ", end="")
    print()

    if ybuf["info"]["open"] == False:
        return

    for node in ybuf["nodes"]:
        # print one node's info
        loc = node["loc"]
        print(f"\nn {loc['level']},{loc['offset']} ", end="")
        for key, val in sorted(node["info"].items()):
            print(f"{key} {val} ", end="")
        print()

        if node["info"]["nkvsets"] == 0:
            continue

        # print info for all kvsets in current node
        for kvset in node["kvsets"]:
            index = kvset["index"]
            print(f"k {loc['level']},{loc['offset']},{index} ", end="")
            for key, val in sorted(kvset.items()):
                if key == "kblks":
                    print("ids ", end=""),
                    for kblk in val:
                        print(f"{hex(int(kblk))} ", end="")
                elif key == "vblks":
                    print("/ ", end=""),
                    if val:
                        for vblk in val:
                            print(f"{hex(int(vblk))} ", end="")
                elif key in oids:
                    print(f"{key} {hex(int(val))} ", end="")
                elif key != "index":
                    print(f"{key} {val} ", end="")
            print()


def cmd_parser_setup() -> argparse.ArgumentParser:
    desc = (
        "print cn tree shape\n\n"
        "example1: %(prog)s mp1 kvs1 -r3\n"
        "example2: cat file.yml | %(prog)s"
    )
    p = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument(
        "-r",
        "--refresh",
        type=int,
        metavar="N",
        help="refresh every N secs",
        required=False,
    )
    p.add_argument("-y", "--yaml", help="output in yaml", action="store_true")

    p.add_argument("kvdb_home", help="kvdb home dir")
    p.add_argument("kvs", help="kvs name")

    return p


def get_args():
    p = cmd_parser_setup()
    return p.parse_args()


def cmd_help():
    p = cmd_parser_setup()
    p.print_help()


def process_stdin() -> int:
    if sys.stdin.isatty():
        cmd_help()
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

    opt = get_args()

    if not opt.kvdb_home or not opt.kvs:
        cmd_help()

    sock = os.path.join(opt.kvdb_home, 'hse.sock')
    url = f"http://localhost/kvdb/kvs/{opt.kvs}/cn/tree"

    if opt.refresh:
        sp.call("clear")

    while True:
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
            return -1

        if opt.yaml:
            print(buf)
        else:
            ybuf = yaml.safe_load(buf)
            full_tree(ybuf)

        if not opt.refresh:
            return 0

        time.sleep(opt.refresh)
        sp.call("clear")


if __name__ == "__main__":
    rc = main()
    sys.exit(rc)
