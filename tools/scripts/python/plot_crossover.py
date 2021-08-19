# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2020-2021 Micron Technology, Inc. All rights reserved.

from bokeh.plotting import figure, output_file, save, gridplot
from bokeh.layouts import layout, column, row
from bokeh.models import Div

import pandas as pd
import os, re
import yaml
import argparse
from multiprocessing import Pool, Queue
import threading

from lib.tree_shape import TreeShape
from lib.crossover import Crossover
from lib.util import Util


def parse_cmdline():
    desc = (
        "Plot Crossover data\n\n"
        "example: %(prog)s --ouput_file=/tmp/plot.html --test_dir=/var/tmp/test\n"
    )
    p = argparse.ArgumentParser(
        description=desc, formatter_class=argparse.RawTextHelpFormatter
    )
    p.add_argument(
        "-o", "--out_file", type=str, help="html output file", required=False
    )
    p.add_argument("-i", "--test_dir", type=str, help="test directory", required=False)

    return p.parse_args()


def make_plots(arg_dict):
    u = Util()

    vlen = arg_dict["vlen"]
    nkey = arg_dict["nkey"]
    tree_path = arg_dict["tree_path"]
    crossover_path = arg_dict["crossover_path"]

    title = "vlen: {} nkey: {} size: {}".format(
        vlen, u.humanize(nkey), u.humanize(nkey * vlen)
    )
    heading = Div(
        text=f"""
    <hr style="width:100%">
    <h2>{title}</h2>
    """,
        width=1000,
    )

    ts = TreeShape(fanout=16, width=500, height=500)
    c = Crossover(width=1500, height=500)

    ybuf = u.file_to_yaml(tree_path)
    d = ts.process_yaml(ybuf)
    ts.add_tree_data(d)
    tot_kvsets, c_kvsets_avg, g_kvsets_avg = ts.avg_nkvset(ybuf, pivot=2)
    tree_plot, slider = ts.plot_graph(
        title="nkvsets Get: {} Cursor: {} Total: {}".format(
            g_kvsets_avg, c_kvsets_avg, tot_kvsets
        )
    )

    df = c.df_for_nkeys(
        nkey_dir=crossover_path, c_avg_nkvset=c_kvsets_avg, g_avg_nkvset=g_kvsets_avg
    )
    crossover_plot = c.plot(df=df)

    # Output
    arg_dict["plots"] = column(heading, row(tree_plot, crossover_plot))


def scan_dirs(basepath):
    """
    Returns a dictionary with the following mapping
        (vlen, klen) --> [tree_path, crossover_path]
    """
    flist = os.listdir(basepath)
    pdict = {}
    for vlen_dir in sorted(flist):
        c = re.compile(r"rr_(\d+)")
        d = c.search(vlen_dir)
        if d == None:
            continue

        vlen = int(d.group(1))

        loadpath = "{}/{}/load/".format(basepath, vlen_dir)
        c = re.compile(r"cn_metrics_raw_(\d+).log")
        for tree in os.listdir(loadpath):
            pat = c.search(tree)
            if pat == None:
                continue

            nkey = int(pat.group(1))
            tree_path = "{}/{}/load/{}".format(basepath, vlen_dir, tree)
            pdict[(vlen, nkey)] = [tree_path]

        runpath = "{}/{}/run/".format(basepath, vlen_dir)
        nkey_pat = re.compile(r"keys_(\d+)")
        for nkey_dir in os.listdir(runpath):
            nkey = int(nkey_pat.search(nkey_dir).group(1))
            filepath = "{}/{}/run/{}".format(basepath, vlen_dir, nkey_dir)
            pdict[(vlen, nkey)].append(filepath)

    return pdict


def main():
    opt = parse_cmdline()
    outpath = opt.out_file

    pdict = scan_dirs(opt.test_dir)

    args = []
    for k in sorted(pdict, key=lambda s: (s[0], s[1])):
        arg_dict = {}
        arg_dict["vlen"] = k[0]
        arg_dict["nkey"] = k[1]
        arg_dict["tree_path"] = pdict[k][0]
        arg_dict["crossover_path"] = pdict[k][1]
        args.append(arg_dict)

    threads = []
    for arg in args:
        t = threading.Thread(target=make_plots, args=(arg,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    intro = Div(
        text="""
    <h1>Crossover</h1>
    <p>
    This set of plots compares get performance with cursor performance as it varies with the burst length.<br>
    The keys in the kvs is evenly distributed across 64 prefixes. At each stage the test adds more suffixes<br>
    for each prefix and this load is followed by warming up mcache and then performing get and cursor operation<br>
    for various burstlens.<br>
    </p>

    <p>
    Each row represents a distinct tuple of number of keys and value length. The first plot shows the tree shape right<br>
    after load (after allowing the cn tree shape to quiesce). The next 3 plots show the following:
    <ul>
    <li>Throughput: Number of cursor reads or point gets per second.</li>
    <li>Latency Mean: A plot of the mean latency of each value read.</li>
    <li>Latency StdDev: A plot of the Standard deviation values for the latencies (noremalized to the mean).</li>
    </ul>
    </p>

    <p>
    KVS Pfxlen: 8bytes (Equal to the prefix length of the multi-segmented keys).<br>
    System Memory: 256G<br>
    Value Length: 256bytes<br>
    </p>
    """,
        width=1000,
    )

    subplots = [intro]
    for r in args:
        subplots.append(r["plots"])

    output_file(outpath)
    canvas = layout(subplots)
    save(canvas)


if __name__ == "__main__":
    main()
