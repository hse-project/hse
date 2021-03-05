import os
import argparse
import time
import subprocess as sp
import yaml

from bokeh.plotting import output_file, save
from bokeh.layouts import layout

from lib.tree_shape import TreeShape
from lib.util import Util

def parse_cmdline() -> argparse.ArgumentParser:
    desc = "Collect tree snapshots\n\n" \
           "example: %(prog)s -d /var/tmp/tree_shapes -o /tmp/tree_timeline.html"

    p = argparse.ArgumentParser(description=desc,
                                formatter_class=argparse.RawTextHelpFormatter)

    p.add_argument('-d', '--yaml_dir', type=str, help='yaml input dir', required=True);
    p.add_argument('-f', '--fanout', type=str, help='Fanout of the kvs', required=True);
    p.add_argument('-o', '--html_file', type=str, help='html output file', required=True)

    return p.parse_args()

def main():
    opt = parse_cmdline()
    flist = os.listdir(opt.yaml_dir)

    ts = TreeShape(fanout=opt.fanout, width=900, height=900)
    u = Util()
    i = 0
    for f in sorted(flist):
        ybuf = u.file_to_yaml(f'{opt.yaml_dir}/{f}')
        d = ts.process_yaml(ybuf)
        if d != None:
            ts.add_tree_data(d)
        i += 1

    p, slider = ts.plot_graph(title='cN Tree Shape')
    if p == None:
        print('Empty List')
        return -1

    if slider:
        composite = [[p], [slider]]
    else:
        composite = [[p]]

    output_file(opt.html_file)
    plot = layout(composite)
    save(plot)
    print(f'Plot: {opt.html_file}')

if __name__ == '__main__':
    main()

