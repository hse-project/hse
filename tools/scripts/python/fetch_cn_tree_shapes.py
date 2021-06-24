#!/usr/bin/env python3
import argparse
import datetime
import os
import time
import subprocess
import sys

import requests_unixsocket
import yaml


TZ_LOCAL = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo


def dt():
    return datetime.datetime.now(tz=TZ_LOCAL).isoformat()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--interval", "-i", type=int, default=10)
    parser.add_argument("--output-dir", "-d", default="cn_tree_shapes")

    grp = parser.add_mutually_exclusive_group()
    grp.add_argument("--kvs", nargs="+")
    grp.add_argument("--mpool")

    args = parser.parse_args()

    if not args.kvs and not args.mpool:
        print("One of --kvs, or --mpool is required. Quitting.")
        sys.exit(1)

    if os.path.exists(args.output_dir):
        print("%s already exists. Quitting." % args.output_dir)
        sys.exit(1)

    print(args.mpool)
    if args.mpool:
        kvslist = []

        cmd = ["hse", "kvdb", "list", "-v"]
        cmd += [args.mpool]

        out = subprocess.check_output(cmd)
        data = yaml.safe_load(out)
        if "kvdbs" in data and data["kvdbs"]:
            for record in data["kvdbs"]:
                kvslist.extend(record["kvslist"])
    else:
        kvslist = args.kvs

    url = {}
    dirpath = {}
    sockpath = {}

    for kvs in kvslist:
        kvdbname, kvsname = kvs.split("/")
        socket_path = os.getenv('HSE_REST_SOCK_PATH')
        url[kvs] = "http+unix://%s/mpool/%s/kvs/%s/cn/tree" % (
            socket_path.replace("/", "%2F"),
            kvdbname,
            kvsname,
        )

        dirpath[kvs] = os.path.join(args.output_dir, kvdbname, kvsname)
        os.makedirs(dirpath[kvs])

        sockpath[kvs] = socket_path

    session = requests_unixsocket.Session()

    counter = 1

    while True:
        t1 = time.time()
        for kvs in kvslist:
            path = os.path.join(dirpath[kvs], "cn_tree_%06d.yaml" % counter)

            if os.path.exists(sockpath[kvs]):
                response = session.get(url[kvs])
            else:
                print(
                    "[%s] Iteration #%06d of KVS %s path %s does not exist, "
                    "KVS not open? Skipping." % (dt(), counter, kvs, sockpath[kvs])
                )
                continue

            if response.text.startswith("Usage:"):
                print(
                    "[%s] Iteration #%06d of KVS %s returned usage message, "
                    "KVS not open? Skipping." % (dt(), counter, kvs)
                )
            else:
                print("[%s] Writing to path %s" % (dt(), path))
                with open(path, "w") as fp:
                    fp.write(response.text)

        time.sleep(args.interval - ((time.time() - t1) % args.interval))
        counter += 1


if __name__ == "__main__":
    main()
